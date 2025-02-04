// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>

#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <pubkey.h>
#include <uint256.h>

#include <debugger/interpreter.h>
#include <inttypes.h> // PRId64 ...
#include <util/strencodings.h> // for Join<>
#include <debugger/script.h>
#include <tinyformat.h>

// typedef valtype, inline void set_* are in debugger/interpreter.h

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() < CPubKey::COMPRESSED_SIZE) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != CPubKey::SIZE) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != CPubKey::COMPRESSED_SIZE) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

bool static IsCompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() != CPubKey::COMPRESSED_SIZE) {
        //  Non-canonical public key: invalid length for compressed key
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03) {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integer (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError* serror) {
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    // https://bitcoin.stackexchange.com/a/12556:
    //     Also note that inside transaction signatures, an extra hashtype byte
    //     follows the actual signature data.
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    // If the S value is above the order of the curve divided by two, its
    // complement modulo the order could have been used instead, which is
    // one byte shorter when encoded correctly.
    if (!CPubKey::CheckLowS(vchSigCopy)) {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    } else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckPubKeyEncoding(const valtype &vchPubKey, unsigned int flags, const SigVersion &sigversion, ScriptError* serror) {
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    // Only compressed keys are accepted in segwit
    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigversion == SigVersion::WITNESS_V0 && !IsCompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    // Excludes OP_1NEGATE, OP_1-16 since they are by definition minimal
    assert(0 <= opcode && opcode <= OP_PUSHDATA4);
    if (data.size() == 0) {
        // Should have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Should have used OP_1 .. OP_16.
        return false;
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Should have used OP_1NEGATE.
        return false;
    } else if (data.size() <= 75) {
        // Must have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Must have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Must have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

int FindAndDelete(CScript& script, const CScript& b)
{
    int nFound = 0;
    if (b.empty())
        return nFound;
    CScript result;
    CScript::const_iterator pc = script.begin(), pc2 = script.begin(), end = script.end();
    opcodetype opcode;
    do
    {
        result.insert(result.end(), pc2, pc);
        while (static_cast<size_t>(end - pc) >= b.size() && std::equal(b.begin(), b.end(), pc))
        {
            pc = pc + b.size();
            ++nFound;
        }
        pc2 = pc;
    }
    while (script.GetOp(pc, opcode));

    if (nFound > 0) {
        result.insert(result.end(), pc2, end);
        script = std::move(result);
    }

    return nFound;
}

static bool EvalChecksigPreTapscript(ScriptExecutionEnvironment& env, const valtype& vchSig, const valtype& vchPubKey, CScript::const_iterator pbegincodehash, CScript::const_iterator pend, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& fSuccess)
{
    auto& pretend_valid_map = env.pretend_valid_map;
    auto& pretend_valid_pubkeys = env.pretend_valid_pubkeys;

    btc_logf("Eval Checksig Pre-Tapscript\n");
    assert(sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0);

    // Subset of script starting at the most recent codeseparator
    CScript scriptCode(pbegincodehash, pend);

    // Drop the signature in pre-segwit scripts but not segwit scripts
    if (sigversion == SigVersion::BASE) {
        int found = FindAndDelete(scriptCode, CScript() << vchSig);
        if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
            return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
    }

    std::string pub_str = HexStr(vchPubKey);
    if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
        //serror is set
        if (pretend_valid_map.size() > 0) {
            fprintf(stderr, "note: pubkey not found in pretend set: %s not in (%s)\n", pub_str.c_str(), Join<std::set<valtype>,std::vector<unsigned char>>(pretend_valid_pubkeys, ", ", JoinHexStrFun).c_str());
        }
        return false;
    }
    fSuccess = checker.CheckECDSASignature(vchSig, vchPubKey, scriptCode, sigversion);
    if (!fSuccess && pretend_valid_map.size() > 0) {
        fprintf(stderr, "note: pubkey not found in pretend set: %s not in (%s)\n", pub_str.c_str(), Join<std::set<valtype>,std::vector<unsigned char>>(pretend_valid_pubkeys, ", ", JoinHexStrFun).c_str());
    }

    if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

    return true;
}

static bool EvalChecksigTapscript(const valtype& sig, const valtype& pubkey, ScriptExecutionData& execdata, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& success)
{
    btc_logf("Eval Checksig Tapscript\n");
    assert(sigversion == SigVersion::TAPSCRIPT);

    /*
     *  The following validation sequence is consensus critical. Please note how --
     *    upgradable public key versions precede other rules;
     *    the script execution fails when using empty signature with invalid public key;
     *    the script execution fails when using non-empty invalid signature.
     */
    success = !sig.empty();
    btc_logf("- sig must not be empty: %s\n", success ? "ok" : "it is empty");
    if (success) {
        // Implement the sigops/witnesssize ratio test.
        // Passing with an upgradable public key version is also counted.
        assert(execdata.m_validation_weight_left_init);
        execdata.m_validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        btc_logf("- validation weight - %lld -> %lld\n", VALIDATION_WEIGHT_PER_SIGOP_PASSED, execdata.m_validation_weight_left);
        if (execdata.m_validation_weight_left < 0) {
            return set_error(serror, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
        }
    }
    if (pubkey.size() == 0) {
        btc_logf("- check failed: no pubkeys\n");
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    } else if (pubkey.size() == 32) {
        btc_logf("- 32 byte pubkey (new type); schnorr sig check\n");
        if (success && !checker.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror)) {
            btc_logf("- schnorr sig check failed\n");
            return false; // serror is set
        }
    } else {
        /*
         *  New public key version softforks should be defined before this `else` block.
         *  Generally, the new code should not do anything but failing the script execution. To avoid
         *  consensus bugs, it should not modify any existing values (including `success`).
         */
        btc_logf("- old style pubkey\n");
        if ((flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE) != 0) {
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
        }
    }

    return true;
}

/** Helper for OP_CHECKSIG, OP_CHECKSIGVERIFY, and (in Tapscript) OP_CHECKSIGADD.
 *
 * A return value of false means the script fails entirely. When true is returned, the
 * success variable indicates whether the signature check itself succeeded.
 */
static bool EvalChecksig(ScriptExecutionEnvironment& env, const valtype& sig, const valtype& pubkey, CScript::const_iterator pbegincodehash, CScript::const_iterator pend, ScriptExecutionData& execdata, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror, bool& success)
{
    btc_taproot_logf("EvalChecksig() sigversion=%d\n", sigversion);
    auto& pretend_valid_map = env.pretend_valid_map;
    auto& pretend_valid_pubkeys = env.pretend_valid_pubkeys;
    std::string sig_str = HexStr(sig);
    std::string pub_str = HexStr(pubkey);
    if (pretend_valid_pubkeys.count(pubkey)) {
        success = pretend_valid_map.count(sig) && pretend_valid_map.at(sig) == pubkey;
        if (success) {
            return true;
        }
        fprintf(stderr, "note: pretend signature mismatch: got %s=%s, expected %s=%s\n",
            sig_str.c_str(), pub_str.c_str(),
            pretend_valid_map.count(sig) ? HexStr(pretend_valid_map.at(sig)).c_str() : "<null>",
            pub_str.c_str()
        );
    }
    if (sigversion == SigVersion::TAPROOT) {
        // btcdeb converts taproot spends into actual scripts, but in reality these are checked earlier
        success = checker.CheckSchnorrSignature(sig, pubkey, SigVersion::TAPROOT, execdata);
        return success;
    }
    switch (sigversion) {
    case SigVersion::BASE:
    case SigVersion::WITNESS_V0:
        return EvalChecksigPreTapscript(env, sig, pubkey, pbegincodehash, pend, flags, checker, sigversion, serror, success);
    case SigVersion::TAPSCRIPT:
        return EvalChecksigTapscript(sig, pubkey, execdata, flags, checker, sigversion, serror, success);
    case SigVersion::TAPROOT:
        // Key path spending in Taproot has no script, so this is unreachable.
        break;
    }
    assert(false);
}

bool StepExtended(ScriptExecutionEnvironment& env, CScript::const_iterator& pc, CScript* local_script)
{
    auto& stack = env.stack;
    auto& serror = env.serror;

    valtype vch1, vch2, vch3;
    switch (env.opcode) {
    case OP_CAT:
        // (x1 x2 -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        vch1.insert(vch1.end(), vch2.begin(), vch2.end());
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_SUBSTR:
        // (in begin size -- out)
        if (stack.size() < 3) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-3);
        vch2 = stacktop(-2);
        vch3 = stacktop(-1);

        {
            // begin
            const CScriptNum begin(vch2, env.fRequireMinimal, 2);
            if (begin < 0) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            // size
            const CScriptNum size(vch3, env.fRequireMinimal, 2);
            if (size < 0 || begin + size > vch1.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            if (begin > 0) {
                vch1.erase(vch1.begin(), vch1.begin() + begin.getint());
            }
            if (size < vch1.size()) {
                vch1.erase(vch1.begin() + size.getint(), vch1.end());
            }
        }
        popstack(stack);
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_LEFT:
    case OP_RIGHT:
        // (in size -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        {
            // size
            const CScriptNum size(vch2, env.fRequireMinimal, 2);
            if (size < 0 || size > vch1.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
            if (size < vch1.size()) {
                if (env.opcode == OP_LEFT) {
                    vch1.erase(vch1.begin() + size.getint(), vch1.end());
                } else {
                    vch1.erase(vch1.begin(), vch1.end() - size.getint());
                }
            }
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_INVERT:
        // (in -- out)
        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-1);
        for (size_t i = 0; i < vch1.size(); ++i) vch1[i] = ~vch1[i];
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_AND:
    case OP_OR:
    case OP_XOR:
        // (x1 x2 -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        if (vch1.size() != vch2.size()) return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
        if (env.opcode == OP_AND) {
            for (size_t i = 0; i < vch1.size(); ++i) vch1[i] &= vch2[i];
        } else if (env.opcode == OP_OR) {
            for (size_t i = 0; i < vch1.size(); ++i) vch1[i] |= vch2[i];
        } else if (env.opcode == OP_XOR) {
            for (size_t i = 0; i < vch1.size(); ++i) vch1[i] ^= vch2[i];
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_2MUL:
        // (in -- out)
        if (stack.size() < 1) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-1);
        {
            // multiply by 2 = left-shift one bit
            uint16_t carry = 0;
            for (size_t i = 0; i < vch1.size(); ++i) {
                uint16_t v = vch1[i];
                v = (v << 1) | carry;
                carry = v >> 8;
                vch1[i] = v & 0xff;
            }
            if (carry) vch1.push_back(carry);
        }
        popstack(stack);
        pushstack(stack, vch1);
        return true;

    case OP_MUL:
    case OP_DIV:
    case OP_MOD:
    case OP_LSHIFT:
    case OP_RSHIFT:
        // (a b -- out)
        if (stack.size() < 2) return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
        vch1 = stacktop(-2);
        vch2 = stacktop(-1);
        {
            CScriptNum num1(vch1, env.fRequireMinimal, 5);
            CScriptNum num2(vch2, env.fRequireMinimal, 5);
            switch (env.opcode) {
            case OP_MUL: num1 = num1 * num2; break;
            case OP_DIV: num1 = num1 / num2; break;
            case OP_MOD: num1 = num1 % num2; break;
            case OP_LSHIFT: num1 = num1 << num2; break;
            case OP_RSHIFT: num1 = num1 >> num2; break;
            default: assert(0);
            }
            vch1 = num1.getvch();
        }
        popstack(stack);
        popstack(stack);
        pushstack(stack, vch1);
        return true;
    default: assert(0);
    }
}

bool StepScript(ScriptExecutionEnvironment& env, CScript::const_iterator& pc, CScript* local_script)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    // static const CScriptNum bnFalse(0);
    // static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    // static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    auto& pend = env.pend;
    auto& pbegincodehash = env.pbegincodehash;
    auto& opcode = env.opcode;
    auto& vchPushValue = env.vchPushValue;
    auto& vfExec = env.vfExec;
    auto& altstack = env.altstack;
    auto& nOpCount = env.nOpCount;
    auto& fRequireMinimal = env.fRequireMinimal;
    auto& stack = env.stack;
    auto& script = local_script ? *local_script : env.script;
    auto& flags = env.flags;
    auto& checker = env.checker;
    auto& sigversion = env.sigversion;
    auto& serror = env.serror;
    auto& pretend_valid_map = env.pretend_valid_map;
    auto& pretend_valid_pubkeys = env.pretend_valid_pubkeys;
    auto& opcode_pos = env.opcode_pos;
    auto& execdata = env.execdata;

    {
        {
            bool fExec = vfExec.all_true();

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            if (sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) {
                // Note how OP_RESERVED does not count towards the opcode limit.
                if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT) {
                    return set_error(serror, SCRIPT_ERR_OP_COUNT);
                }
            }

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return env.allow_disabled_opcodes
                    ? StepExtended(env, pc, local_script)
                    : set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes (CVE-2010-5137).

            // With SCRIPT_VERIFY_CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is rejected even in an unexecuted branch
            if (opcode == OP_CODESEPARATOR && sigversion == SigVersion::BASE && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
                return set_error(serror, SCRIPT_ERR_OP_CODESEPARATOR);

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                pushstack(stack, vchPushValue);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    pushstack(stack, bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    break;
                }

                case OP_NOP1: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                        if (sigversion == SigVersion::TAPSCRIPT) {
                            // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                            // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                            if (vch.size() > 1 || (vch.size() == 1 && vch[0] != 1)) {
                                return set_error(serror, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
                            }
                        }
                        // Under witness v0 rules it is only a policy rule, enabled through SCRIPT_VERIFY_MINIMALIF.
                        if (sigversion == SigVersion::WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF)) {
                            if (vch.size() > 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                            if (vch.size() == 1 && vch[0] != 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.toggle_top();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;

                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    pushstack(altstack, stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    pushstack(stack, altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    pushstack(stack, vch1);
                    pushstack(stack, vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    pushstack(stack, vch1);
                    pushstack(stack, vch2);
                    pushstack(stack, vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    pushstack(stack, vch1);
                    pushstack(stack, vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    pushstack(stack, vch1);
                    pushstack(stack, vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        pushstack(stack, vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    pushstack(stack, bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    pushstack(stack, vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    pushstack(stack, vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    pushstack(stack, vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    pushstack(stack, bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    pushstack(stack, fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    pushstack(stack, bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    pushstack(stack, bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    pushstack(stack, fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                    else if (opcode == OP_HASH160)
                        CHash160().Write(vch).Finalize(vchHash);
                    else if (opcode == OP_HASH256)
                        CHash256().Write(vch).Finalize(vchHash);
                    popstack(stack);
                    pushstack(stack, vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // If SCRIPT_VERIFY_CONST_SCRIPTCODE flag is set, use of OP_CODESEPARATOR is rejected in pre-segwit
                    // script, even in an unexecuted branch (this is checked above the opcode case statement).

                    // Hash starts after the code separator
                    pbegincodehash = pc;
                    execdata.m_codeseparator_pos = opcode_pos;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);

                    bool fSuccess = true;
                    if (!EvalChecksig(env, vchSig, vchPubKey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, fSuccess)) return false;
                    popstack(stack);
                    popstack(stack);
                    pushstack(stack, fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKSIGADD:
                {
                    // OP_CHECKSIGADD is only available in Tapscript
                    if (sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) {
                        btc_logf("OP_CHECKSIGADD is only available in Tapscript\n");
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }

                    // (sig num pubkey -- num)
                    if (stack.size() < 3) {
                        btc_logf("stack size too small (expected sig, num, pubkey, but size = %zu)\n", stack.size());
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    }

                    const valtype& sig = stacktop(-3);
                    const CScriptNum num(stacktop(-2), fRequireMinimal);
                    const valtype& pubkey = stacktop(-1);

                    bool success = true;
                    if (!EvalChecksig(env, sig, pubkey, pbegincodehash, pend, execdata, flags, checker, sigversion, serror, success)) return false;
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    pushstack(stack, (num + (success ? 1 : 0)).getvch());
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    if (sigversion == SigVersion::TAPSCRIPT) {
                        btc_logf("CHECKMULTISIG(VERIFY) is disabled for Tapscript\n");
                        return set_error(serror, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
                    }

                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    btc_sign_logf("stack has %zu entries [require 1]\n", stack.size());
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    int total_keys = nKeysCount;
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    nOpCount += nKeysCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int ikey = ++i;
                    int starting_key_pos = ikey;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    int ikey2 = nKeysCount + 2;
                    i += nKeysCount;
                    btc_sign_logf("stack has %zu entries [require %d]\n", stack.size(), i);
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    btc_sign_logf("stack has %zu entries [require %d]\n", stack.size(), i);
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        if (sigversion == SigVersion::BASE) {
                            int found = FindAndDelete(scriptCode, CScript() << vchSig);
                            if (found > 0 && (flags & SCRIPT_VERIFY_CONST_SCRIPTCODE))
                                return set_error(serror, SCRIPT_ERR_SIG_FINDANDDELETE);
                        }
                    }
                    btc_sign_logf("scriptCode = %s\n", HexStr(scriptCode).c_str());

                    bool fSuccess = true;
                    btc_sign_logf("looping for multisig\n");
                    while (fSuccess && nSigsCount > 0)
                    {
                        btc_sign_logf("loop: sigs = %d, keys = %d\n", nSigsCount, nKeysCount);
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        std::string sig_str = HexStr(vchSig);
                        std::string pub_str = HexStr(vchPubKey);
                        btc_sign_logf("- got sig %s\n", sig_str.c_str());
                        btc_sign_logf("- got key %s\n", pub_str.c_str());
                        bool fOk;
                        if (pretend_valid_pubkeys.count(vchPubKey)) {
                            fOk = pretend_valid_map.count(vchSig) && pretend_valid_map.at(vchSig) == vchPubKey;
                            if (!fOk) btc_sign_logf("- [mock] wrong pubkey for sig; marking as failed\n");
                        } else {
                            // Note how this makes the exact order of pubkey/signature evaluation
                            // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                            // See the script_(in)valid tests for details.
                            if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                                // serror is set
                                btc_sign_logf("! CheckSignatureEncoding() or CheckPubKeyEncoding() failed!\n");
                                return false;
                            }
                            // Check signature
                            fOk = checker.CheckECDSASignature(vchSig, vchPubKey, scriptCode, sigversion);
                        }
                        btc_sign_logf("- sig check %s\n", fOk ? "succeeded" : "failed");

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount) {
                            fSuccess = false;

                            // see if remaining sigs would have solved for any of the pubkeys
                            auto bsl = btc_sign_logf;
                            auto bsh = btc_sighash_logf;
                            while (nSigsCount > 0) {
                                valtype& vchSig = stacktop(-isig);
                                btc_sign_logf = btc_sighash_logf = btc_logf_dummy;
                                for (int i = starting_key_pos; i < starting_key_pos + total_keys; ++i) {
                                    valtype& vchPubkeyAlt = stacktop(-i);
                                    if (checker.CheckECDSASignature(vchSig, vchPubkeyAlt, scriptCode, sigversion)) {
                                        btc_logf("!!! note: signature %s is probably in the wrong position: it successfully signs a (previous) pubkey %s\n", HexStr(vchSig).c_str(), HexStr(vchPubkeyAlt).c_str());
                                    }
                                }
                                ++isig;
                                --nSigsCount;
                            }
                            btc_sign_logf = bsl;
                            btc_sighash_logf = bsh;
                        }
                    }
                    btc_sign_logf("loop ended in %s state\n", fSuccess ? "successful" : "failure");

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                        if (ikey2 > 0)
                            ikey2--;
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size()) {
                        if (btcdeb_verbose) printf(
                            "\n* * * * * * *\n\n"

                            "Hint: with Segwit activation, the OP_CHECKMULTISIG extra argument must be set to the empty push value (0x). If you are experimenting with older scripts, you may run into a 'Dummy CHECKMULTISIG argument must be zero' error. To move past this, you need to modify the verification flags, disabling the NULLDUMMY flag specifically. I.e. call btcdeb again with -f\"-NULLDUMMY\"\n\n"

                            "* * * * * * *\n\n"
                        ); else printf("Hint: with Segwit activation, the OP_CHECKMULTISIG extra argument must be empty (--verbose for details)\n");
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    }
                    popstack(stack);

                    pushstack(stack, fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                break;

                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }

            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }

    return true;
}

ScriptExecutionEnvironment::ScriptExecutionEnvironment(std::vector<std::vector<unsigned char> >& stack_in, const CScript& script_in, unsigned int flags_in, const BaseSignatureChecker& checker_in)
: script(script_in)
, pend(script.end())
, pbegincodehash(script.begin())
, nOpCount(0)
, fRequireMinimal((flags_in & SCRIPT_VERIFY_MINIMALDATA) != 0)
, stack(stack_in)
, flags(flags_in)
, checker(checker_in)
, opcode_pos(0)
, execdata{}
, allow_disabled_opcodes{false}
{
    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;
}

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror)
{
    ScriptExecutionEnvironment env(stack, script, flags, checker);
    env.execdata = execdata;
    CScript::const_iterator pc = env.script.begin();
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if ((sigversion == SigVersion::BASE || sigversion == SigVersion::WITNESS_V0) && script.size() > MAX_SCRIPT_SIZE) {
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    }
    if (sigversion == SigVersion::TAPSCRIPT && stack.size() > MAX_STACK_SIZE) {
        return set_error(serror, SCRIPT_ERR_STACK_SIZE);
    }

    if (env.script.size() > MAX_SCRIPT_SIZE)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);

    try {
        while (pc < env.pend) {
            if (!StepScript(env, pc)) {
                return false;
            }
            ++env.opcode_pos;
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!env.vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    ScriptExecutionData execdata;
    return EvalScript(stack, script, flags, checker, sigversion, execdata, serror);
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
template <class T>
class CTransactionSignatureSerializer
{
private:
    const T& txTo;             //!< reference to the spending transaction (the one being serialized)
    const CScript& scriptCode; //!< output script being consumed
    const unsigned int nIn;    //!< input index of txTo being signed
    const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const T& txToIn, const CScript& scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        btc_sign_logf(" << scriptCode.size()=%zu - nCodeSeparators=%d\n", scriptCode.size(), nCodeSeparators);
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        btc_sign_logf(" << script:"); print_vec(scriptCode, btc_sign_logf); btc_sign_logf("\n");
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay) {
            btc_sign_logf("    (fAnyoneCanPay: nInput = nIn)\n");
            nInput = nIn;
        }
        // Serialize the prevout
        btc_sign_logf(" << txTo.vin[nInput=%d].prevout = %s\n", nInput, txTo.vin[nInput].prevout.ToString().c_str());
        ::Serialize(s, txTo.vin[nInput].prevout);
        // Serialize the script
        if (nInput != nIn) {
            // Blank out other inputs' signatures
            ::Serialize(s, CScript());
            btc_sign_logf(" << [empty script] (reason: nInput != nIn)\n");
        } else {
            btc_sign_logf("(SerializeScriptCode)\n");
            SerializeScriptCode(s);
        }
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone)) {
            // let the others update at will
            btc_sign_logf(" << sequence = 0 (nInput != nIn && (fHashSingle || fHashNone))\n");
            ::Serialize(s, (int)0);
        } else {
            btc_sign_logf(" << txTo.vin[nInput].nSequence = %u [0x%x]\n", txTo.vin[nInput].nSequence, txTo.vin[nInput].nSequence);
            ::Serialize(s, txTo.vin[nInput].nSequence);
        }
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut());
        else
            ::Serialize(s, txTo.vout[nOutput]);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s) const {
        btc_sign_logf("Serializing transaction\n");
        // Serialize nVersion
        btc_sign_logf(" << txTo.nVersion (%04x), txTo.nType (%04x)\n", txTo.nVersion, txTo.nType);
        int32_t n32bitVersion = txTo.nVersion | (txTo.nType << 16);
        ::Serialize(s, n32bitVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        btc_sign_logf(" << nInputs = %d [compact]\n", nInputs);
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++) {
            btc_sign_logf("(serialize input %d)\n", nInput);
            SerializeInput(s, nInput);
        }
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        btc_sign_logf(" << nOutputs = %d [compact]\n", nOutputs);
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++) {
            btc_sign_logf("(serialize output %d)\n", nOutput);
            SerializeOutput(s, nOutput);
        }
        // Serialize nLockTime
        btc_sign_logf(" << txTo.nLockTime = %d [0x%x]\n", txTo.nLockTime, txTo.nLockTime);
        ::Serialize(s, txTo.nLockTime);
        if (txTo.nVersion == 3 && txTo.nType != TRANSACTION_NORMAL)
            ::Serialize(s, txTo.vExtraPayload);
    }
};

/** Compute the (single) SHA256 of the concatenation of all prevouts of a tx. */
template <class T>
uint256 GetPrevoutsSHA256(const T& txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    btc_sign_logf("- generating prevout hash from %zu ins\n", txTo.vin.size());
    for (const auto& txin : txTo.vin) {
        ss << txin.prevout;
        btc_sign_logf("[+] %s\n", txin.prevout.ToString().c_str());
    }
    return ss.GetSHA256();
}

/** Compute the (single) SHA256 of the concatenation of all nSequences of a tx. */
template <class T>
uint256 GetSequencesSHA256(const T& txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txin : txTo.vin) {
        ss << txin.nSequence;
    }
    return ss.GetSHA256();
}

/** Compute the (single) SHA256 of the concatenation of all txouts of a tx. */
template <class T>
uint256 GetOutputsSHA256(const T& txTo)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txout : txTo.vout) {
        ss << txout;
    }
    return ss.GetSHA256();
}

/** Compute the (single) SHA256 of the concatenation of all amounts spent by a tx. */
uint256 GetSpentAmountsSHA256(const std::vector<CTxOut>& outputs_spent)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txout : outputs_spent) {
        ss << txout.nValue;
    }
    return ss.GetSHA256();
}

/** Compute the (single) SHA256 of the concatenation of all scriptPubKeys spent by a tx. */
uint256 GetSpentScriptsSHA256(const std::vector<CTxOut>& outputs_spent)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const auto& txout : outputs_spent) {
        ss << txout.scriptPubKey;
    }
    return ss.GetSHA256();
}


} // namespace

template <class T>
void PrecomputedTransactionData::Init(const T& txTo, std::vector<CTxOut>&& spent_outputs)
{
    assert(!m_spent_outputs_ready);

    m_spent_outputs = std::move(spent_outputs);
    if (!m_spent_outputs.empty()) {
        assert(m_spent_outputs.size() == txTo.vin.size());
        m_spent_outputs_ready = true;
    }
}

template <class T>
PrecomputedTransactionData::PrecomputedTransactionData(const T& txTo)
{
    Init(txTo, {});
}

// explicit instantiation
template void PrecomputedTransactionData::Init(const CTransaction& txTo, std::vector<CTxOut>&& spent_outputs);
template void PrecomputedTransactionData::Init(const CMutableTransaction& txTo, std::vector<CTxOut>&& spent_outputs);
template PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo);
template PrecomputedTransactionData::PrecomputedTransactionData(const CMutableTransaction& txTo);

static const CHashWriter HASHER_TAPSIGHASH = TaggedHash("TapSighash");
static const CHashWriter HASHER_TAPLEAF = TaggedHash("TapLeaf");
static const CHashWriter HASHER_TAPBRANCH = TaggedHash("TapBranch");
static const CHashWriter HASHER_TAPTWEAK = TaggedHash("TapTweak");

template<typename T>
bool SignatureHashSchnorr(uint256& hash_out, const ScriptExecutionData& execdata, const T& tx_to, uint32_t in_pos, uint8_t hash_type, SigVersion sigversion, const PrecomputedTransactionData& cache)
{
    btc_sign_logf("SignatureHashSchnorr(in_pos=%d, hash_type=%02x)\n", in_pos, hash_type);
    uint8_t ext_flag, key_version;
    switch (sigversion) {
    case SigVersion::TAPROOT:
        ext_flag = 0;
        btc_sign_logf("- taproot sighash\n");
        // key_version is not used and left uninitialized.
        break;
    case SigVersion::TAPSCRIPT:
        ext_flag = 1;
        btc_sign_logf("- tapscript sighash\n");
        // key_version must be 0 for now, representing the current version of
        // 32-byte public keys in the tapscript signature opcode execution.
        // An upgradable public key version (with a size not 32-byte) may
        // request a different key_version with a new sigversion.
        key_version = 0;
        break;
    default:
        btc_sign_logf("- UNKNOWN sighash\n");
        assert(false);
    }
    assert(in_pos < tx_to.vin.size());
    assert(cache.m_bip341_taproot_ready && cache.m_spent_outputs_ready);

    CHashWriter ss = HASHER_TAPSIGHASH;

    // Epoch
    static constexpr uint8_t EPOCH = 0;
    ss << EPOCH;

    // Hash type
    const uint8_t output_type = (hash_type == SIGHASH_DEFAULT) ? SIGHASH_ALL : (hash_type & SIGHASH_OUTPUT_MASK); // Default (no sighash byte) is equivalent to SIGHASH_ALL
    const uint8_t input_type = hash_type & SIGHASH_INPUT_MASK;
    if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))) return false;
    ss << hash_type;

    // Transaction level data
    ss << tx_to.nVersion;
    ss << tx_to.nLockTime;
    if (input_type != SIGHASH_ANYONECANPAY) {
        ss << cache.m_prevouts_single_hash;
        ss << cache.m_spent_amounts_single_hash;
        ss << cache.m_spent_scripts_single_hash;
        ss << cache.m_sequences_single_hash;
    }
    if (output_type == SIGHASH_ALL) {
        ss << cache.m_outputs_single_hash;
    }

    // Data about the input/prevout being spent
    assert(execdata.m_annex_init);
    const bool have_annex = execdata.m_annex_present;
    const uint8_t spend_type = (ext_flag << 1) + (have_annex ? 1 : 0); // The low bit indicates whether an annex is present.
    ss << spend_type;
    if (input_type == SIGHASH_ANYONECANPAY) {
        ss << tx_to.vin[in_pos].prevout;
        ss << cache.m_spent_outputs[in_pos];
        ss << tx_to.vin[in_pos].nSequence;
    } else {
        ss << in_pos;
    }
    if (have_annex) {
        ss << execdata.m_annex_hash;
    }

    // Data about the output (if only one).
    if (output_type == SIGHASH_SINGLE) {
        if (in_pos >= tx_to.vout.size()) return false;
        CHashWriter sha_single_output(SER_GETHASH, 0);
        sha_single_output << tx_to.vout[in_pos];
        ss << sha_single_output.GetSHA256();
    }

    // Additional data for BIP 342 signatures
    if (sigversion == SigVersion::TAPSCRIPT) {
        assert(execdata.m_tapleaf_hash_init);
        ss << execdata.m_tapleaf_hash;
        ss << key_version;
        assert(execdata.m_codeseparator_pos_init);
        ss << execdata.m_codeseparator_pos;
    }

    hash_out = ss.GetSHA256();
    return true;
}

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    assert(nIn < txTo.vin.size());

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return uint256::ONE;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer<T> txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

template <class T>
bool GenericTransactionSignatureChecker<T>::VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    btc_sign_logf("  pubkey.VerifyECDSASignature(sig=%s, sighash=%s):\n", HexStr(vchSig).c_str(), sighash.ToString().c_str());
    bool res = pubkey.Verify(sighash, vchSig);
    btc_sign_logf("  result: %s\n", res ? "success" : "FAILURE");
    return res;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::VerifySchnorrSignature(Span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const
{
    btc_sign_logf("  pubkey.VerifySchnorrSignature(sig=%s, sighash=%s):\n", HexStr(sig).c_str(), sighash.ToString().c_str());
    bool res = pubkey.VerifySchnorr(sighash, sig);
    btc_sign_logf("  result: %s\n", res ? "success" : "FAILURE");
    return res;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckECDSASignature(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
{
    btc_sign_logf("GenericTransactionSignatureChecker::CheckECDSASignature(%zu len sig, %zu len pubkey, sigversion=%d)\n", vchSigIn.size(), vchPubKey.size(), sigversion);
    btc_sign_logf("  sig         = "); print_vec(vchSigIn, btc_sign_logf); btc_sign_logf("\n");
    btc_sign_logf("  pub key     = "); print_vec(vchPubKey, btc_sign_logf); btc_sign_logf("\n");
    btc_sign_logf("  script code = "); print_vec(scriptCode, btc_sign_logf); btc_sign_logf("\n");
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid()) {
        btc_sign_logf("- failed: pubkey is not valid\n");
        return false;
    }

    // Hash type is one byte tacked on to the end of the signature
    std::vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty()) {
        btc_sign_logf("- failed: signature is empty\n");
        return false;
    }
    int nHashType = vchSig.back();
    vchSig.pop_back();
    btc_sign_logf("  hash type   = %02x (%s)\n", nHashType, hashtype_str(nHashType).c_str());

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->txdata);
    btc_sign_logf("  sighash     = %s\n", sighash.ToString().c_str());

    if (!VerifyECDSASignature(vchSig, pubkey, sighash)) {
        btc_sign_logf("- failed: VerifyECDSASignature() failed\n");
        return false;
    }

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey_in, SigVersion sigversion, const ScriptExecutionData& execdata, ScriptError* serror) const
{
    btc_sign_logf("GenericTransactionSignatureChecker::CheckSchnorrSignature(%zu len sig, %zu len pubkey, sigversion=%d)\n", sig.size(), pubkey_in.size(), sigversion);
    btc_sign_logf("  sig         = %s\n", HexStr(sig).c_str());
    btc_sign_logf("  pub key     = %s\n", HexStr(pubkey_in).c_str());

    assert(sigversion == SigVersion::TAPROOT || sigversion == SigVersion::TAPSCRIPT);
    // Schnorr signatures have 32-byte public keys. The caller is responsible for enforcing this.
    if (pubkey_in.size() != 32) {
        btc_sign_logf("- failed (assertion!): pubkey size invalid (%zu should be 32)\n", pubkey_in.size());
        throw std::runtime_error("assertion failed: pubkey_in.size() == 32");
    }
    // Note that in Tapscript evaluation, empty signatures are treated specially (invalid signature that does not
    // abort script execution). This is implemented in EvalChecksigTapscript, which won't invoke
    // CheckSchnorrSignature in that case. In other contexts, they are invalid like every other signature with
    // size different from 64 or 65.
    if (sig.size() != 64 && sig.size() != 65) {
        btc_sign_logf("- failed: signature size invalid (must be 64 or 65 bytes, but is %zu bytes)", sig.size());
        return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_SIZE);
    }

    XOnlyPubKey pubkey{pubkey_in};

    uint8_t hashtype = SIGHASH_DEFAULT;
    if (sig.size() == 65) {
        hashtype = SpanPopBack(sig);
        if (hashtype == SIGHASH_DEFAULT) {
            btc_sign_logf("- failed: hashtype must not be SIGHASH_DEFAULT (%u but it is (%u)", SIGHASH_DEFAULT, hashtype);
            return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE);
        }
    }
    uint256 sighash;
    if (!this->txdata) {
        btc_sign_logf("- failed (assertion!): this->txdata not set\n");
        throw std::runtime_error("assertion failed: this->txdata");
    }
    bool ret = SignatureHashSchnorr(sighash, execdata, *txTo, nIn, hashtype, sigversion, *this->txdata);
    if (!ret) {
        btc_sign_logf("- failed generating schnorr signature hash\n");
        return set_error(serror, SCRIPT_ERR_SCHNORR_SIG_HASHTYPE);
    }
    btc_sign_logf("- schnorr sighash = %s\n", sighash.ToString().c_str());
    if (!VerifySchnorrSignature(sig, pubkey, sighash)) {
        btc_sign_logf("- schnorr signature verification ***FAILED***\n");
        return set_error(serror, SCRIPT_ERR_SCHNORR_SIG);
    }
    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
        (txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
        (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
    ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
        return false;

    return true;
}

template <class T>
bool GenericTransactionSignatureChecker<T>::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
        (txToSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
    )) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

// explicit instantiation
template class GenericTransactionSignatureChecker<CTransaction>;
template class GenericTransactionSignatureChecker<CMutableTransaction>;

static bool ExecuteWitnessScript(const Span<const valtype>& stack_span, const CScript& scriptPubKey, unsigned int flags, SigVersion sigversion, const BaseSignatureChecker& checker, ScriptExecutionData& execdata, ScriptError* serror)
{
    btc_logf("Executing witness program with sigversion %d\n", sigversion);
    std::vector<valtype> stack{stack_span.begin(), stack_span.end()};

    if (sigversion == SigVersion::TAPSCRIPT) {
        // OP_SUCCESSx processing overrides everything, including stack element size limits
        CScript::const_iterator pc = scriptPubKey.begin();
        while (pc < scriptPubKey.end()) {
            opcodetype opcode;
            if (!scriptPubKey.GetOp(pc, opcode)) {
                // Note how this condition would not be reached if an unknown OP_SUCCESSx was found
                btc_logf("- script pub key GetOp failed\n");
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }
            // New opcodes will be listed here. May use a different sigversion to modify existing opcodes.
            if (IsOpSuccess(opcode)) {
                btc_logf("- success op (%s)\n", flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS ? "discouraged; failing" : "allowed; succeeding");
                if (flags & SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS) {
                    return set_error(serror, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
                }
                return set_success(serror);
            }
        }

        // Tapscript enforces initial stack size limits (altstack is empty here)
        if (stack.size() > MAX_STACK_SIZE) return set_error(serror, SCRIPT_ERR_STACK_SIZE);
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for (const valtype& elem : stack) {
        if (elem.size() > MAX_SCRIPT_ELEMENT_SIZE) return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }

    // Run the script interpreter.
    if (!EvalScript(stack, scriptPubKey, flags, checker, sigversion, execdata, serror)) return false;

    // Scripts inside witness implicitly require cleanstack behaviour
    if (stack.size() != 1) return set_error(serror, SCRIPT_ERR_CLEANSTACK);
    if (!CastToBool(stack.back())) return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}

bool VerifyTaprootCommitment(const std::vector<unsigned char>& control, const std::vector<unsigned char>& program, const CScript& script, uint256& tapleaf_hash)
{
    btc_taproot_logf("Verifying taproot commitment:\n");
    btc_taproot_logf("Verifying taproot commitment:\n");
    btc_taproot_logf("- control  = %s\n", HexStr(control).c_str());
    btc_taproot_logf("- program  = %s\n", HexStr(program).c_str());
    btc_taproot_logf("- script   = %s\n", HexStr(script).c_str());
    const int path_len = (control.size() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    btc_taproot_logf("- path len = %d\n", path_len);
    //! The inner pubkey (x-only, so no Y coordinate parity).
    const XOnlyPubKey p{uint256(std::vector<unsigned char>(control.begin() + 1, control.begin() + TAPROOT_CONTROL_BASE_SIZE))};
    //! The output pubkey (taken from the scriptPubKey).
    const XOnlyPubKey q{uint256(program)};
    // Compute the tapleaf hash.
    tapleaf_hash = (CHashWriter(HASHER_TAPLEAF) << uint8_t(control[0] & TAPROOT_LEAF_MASK) << script).GetSHA256();
    // Compute the Merkle root from the leaf and the provided path.
    uint256 k = tapleaf_hash;
    btc_taproot_logf("- p        = %s\n", p.ToString().c_str());
    btc_taproot_logf("- q        = %s\n", q.ToString().c_str());
    btc_taproot_logf("- k        = %s          (tap leaf hash)\n", k.ToString().c_str());
    std::string k_desc = strprintf("TapLeaf(0x%02x || %s)", uint8_t(control[0] & TAPROOT_LEAF_MASK), HexStr(script).c_str());
    btc_taproot_logf("  (%s)\n", k_desc.c_str());
    btc_taproot_logf("- looping over path (0..%d)\n", path_len-1);
    for (int i = 0; i < path_len; ++i) {
        CHashWriter ss_branch{HASHER_TAPBRANCH};
        Span<const unsigned char> node(control.data() + TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i, TAPROOT_CONTROL_NODE_SIZE);
        if (std::lexicographical_compare(k.begin(), k.end(), node.begin(), node.end())) {
            btc_taproot_logf("  - %d: node = %02x...; taproot control node match -> k first\n", i, node[0]);
            k_desc = strprintf("TapBranch(%s || Span<%d,%zu>=%s)", k_desc.c_str(), TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i, TAPROOT_CONTROL_NODE_SIZE, HexStr(node).c_str());
            ss_branch << k << node;
        } else {
            btc_taproot_logf("  - %d: node = %02x...; taproot control node mismatch -> k second\n", i, node[0]);
            k_desc = strprintf("TapBranch(Span<%d,%zu>=%s || %s)", TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * i, TAPROOT_CONTROL_NODE_SIZE, HexStr(node).c_str(), k_desc.c_str());
            ss_branch << node << k;
        }
        btc_taproot_logf("  (%s)\n", k_desc.c_str());
        k = ss_branch.GetSHA256();
        btc_taproot_logf("  - %d: k -> %s\n", i, k.ToString().c_str());
    }
    k_desc = strprintf("TapTweak(internal_pubkey=%s || %s)", HexStr(MakeSpan(p)).c_str(), k_desc.c_str());
    // Compute the tweak from the Merkle root and the inner pubkey.
    k = (CHashWriter(HASHER_TAPTWEAK) << MakeSpan(p) << k).GetSHA256();
    btc_taproot_logf("- final k  = %s\n", k.ToString().c_str());
    btc_taproot_logf("  (%s)\n", k_desc.c_str());
    // Verify that the output pubkey matches the tweaked inner pubkey, after correcting for parity.
    bool res = q.CheckPayToContract(p, k, control[0] & 1);
    btc_taproot_logf("- q.CheckPayToContract(p, k, %d) == %s\n", control[0] & 1, res ? "success" : "failure");
    return res;
}

static bool VerifyWitnessProgram(const CScriptWitness& witness, int witversion, const std::vector<unsigned char>& program, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror, bool is_p2sh)
{
    CScript exec_script; //!< Actually executed script (last stack item in P2WSH; implied P2PKH script in P2WPKH; leaf script in P2TR)
    Span<const valtype> stack{witness.stack};
    ScriptExecutionData execdata;

    if (witversion == 0) {
        if (program.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            // BIP141 P2WSH: 32-byte witness v0 program (which encodes SHA256(script))
            if (stack.size() == 0) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
            }
            const valtype& script_bytes = SpanPopBack(stack);
            exec_script = CScript(script_bytes.begin(), script_bytes.end());
            uint256 hash_exec_script;
            CSHA256().Write(&exec_script[0], exec_script.size()).Finalize(hash_exec_script.begin());
            if (memcmp(hash_exec_script.begin(), program.data(), 32)) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::WITNESS_V0, checker, execdata, serror);
        } else if (program.size() == WITNESS_V0_KEYHASH_SIZE) {
            // BIP141 P2WPKH: 20-byte witness v0 program (which encodes Hash160(pubkey))
            if (stack.size() != 2) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
            }
            exec_script << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::WITNESS_V0, checker, execdata, serror);
        } else {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
        }
    } else if (witversion == 1 && program.size() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh) {
        // BIP341 Taproot: 32-byte non-P2SH witness v1 program (which encodes a P2C-tweaked pubkey)
        if (!(flags & SCRIPT_VERIFY_TAPROOT)) return set_success(serror);
        if (stack.size() == 0) return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
        if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
            // Drop annex (this is non-standard; see IsWitnessStandard)
            const valtype& annex = SpanPopBack(stack);
            execdata.m_annex_hash = (CHashWriter(SER_GETHASH, 0) << annex).GetSHA256();
            execdata.m_annex_present = true;
        } else {
            execdata.m_annex_present = false;
        }
        execdata.m_annex_init = true;
        if (stack.size() == 1) {
            // Key path spending (stack size is 1 after removing optional annex)
            if (!checker.CheckSchnorrSignature(stack.front(), program, SigVersion::TAPROOT, execdata, serror)) {
                return false; // serror is set
            }
            return set_success(serror);
        } else {
            // Script path spending (stack size is >1 after removing optional annex)
            const valtype& control = SpanPopBack(stack);
            const valtype& script_bytes = SpanPopBack(stack);
            exec_script = CScript(script_bytes.begin(), script_bytes.end());
            if (control.size() < TAPROOT_CONTROL_BASE_SIZE || control.size() > TAPROOT_CONTROL_MAX_SIZE || ((control.size() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE) != 0) {
                return set_error(serror, SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE);
            }
            if (!VerifyTaprootCommitment(control, program, exec_script, execdata.m_tapleaf_hash)) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
            execdata.m_tapleaf_hash_init = true;
            if ((control[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                // Tapscript (leaf version 0xc0)
                execdata.m_validation_weight_left = ::GetSerializeSize(witness.stack, PROTOCOL_VERSION) + VALIDATION_WEIGHT_OFFSET;
                execdata.m_validation_weight_left_init = true;
                return ExecuteWitnessScript(stack, exec_script, flags, SigVersion::TAPSCRIPT, checker, execdata, serror);
            }
            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION);
            }
            return set_success(serror);
        }
    } else {
        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
        }
        // Other version/size/p2sh combinations return true for future softfork compatibility
        return true;
    }
    // There is intentionally no return statement here, to be able to use "control reaches end of non-void function" warnings to detect gaps in the logic above.
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    static const CScriptWitness emptyWitness;
    if (witness == nullptr) {
        witness = &emptyWitness;
    }
    bool hadWitness = false;

    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    // scriptSig and scriptPubKey must be evaluated sequentially on the same stack
    // rather than being simply concatenated (see CVE-2010-5141)
    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, SigVersion::BASE, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, SigVersion::BASE, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Bare witness programs
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            hadWitness = true;
            if (scriptSig.size() != 0) {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
            }
            if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror, /* is_p2sh */ false)) {
                return false;
            }
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.resize(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, SigVersion::BASE, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS) {
            if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
                hadWitness = true;
                if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
                if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror, /* is_p2sh */ true)) {
                    return false;
                }
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.resize(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS) {
        // We can't check for correct unexpected witness data if P2SH was off, so require
        // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        // possible, which is not a softfork.
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (!hadWitness && !witness->IsNull()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
    }

    return set_success(serror);
}

size_t static WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness)
{
    if (witversion == 0) {
        if (witprogram.size() == WITNESS_V0_KEYHASH_SIZE)
            return 1;

        if (witprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE && witness.stack.size() > 0) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }

    // Future flags may be implemented here.
    return 0;
}

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    static const CScriptWitness witnessEmpty;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
        return 0;
    }
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty);
    }

    if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
        CScript::const_iterator pc = scriptSig.begin();
        std::vector<unsigned char> data;
        while (pc < scriptSig.end()) {
            opcodetype opcode;
            scriptSig.GetOp(pc, opcode, data);
        }
        CScript subscript(data.begin(), data.end());
        if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
            return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty);
        }
    }

    return 0;
}
