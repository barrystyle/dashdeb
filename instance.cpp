#include <script/interpreter.h>
#include <util/strencodings.h>
#include <policy/policy.h>
#include <streams.h>
#include <pubkey.h>
#include <value.h>
#include <vector>

#include <instance.h>

static bool DecodeHexTx(CMutableTransaction& tx, const std::string& strHexTx)
{
    if (!IsHex(strHexTx)) {
        fprintf(stderr, "found nonhex characters in input\n");
        return false;
    }

    std::vector<unsigned char> txData(ParseHex(strHexTx));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    ssData >> tx;

    return true;
}

CTransactionRef parse_tx(const char* p) {
    std::vector<unsigned char> txData;
    if (!TryHex(p, txData)) {
        fprintf(stderr, "failed to parse tx hex string\n");
        return nullptr;
    }

    //! convert to string for native dash routine
    std::string hexData(p);
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hexData)) {
        fprintf(stderr, "error with transaction (unknown)\n");
        return nullptr;
    }

    CTransactionRef tx = MakeTransactionRef(CTransaction(mtx));
    return tx;
}

bool Instance::parse_transaction(const char* txdata, bool parse_amounts) {
    // parse until we run out of amounts, if requested
    const char* p = txdata;
    if (parse_amounts) {
        while (1) {
            const char* c = p;
            while (*c && *c != ',' && *c != ':') ++c;
            if (!*c) {
                if (amounts.size() == 0) {
                    // no amounts provided
                    break;
                }
                fprintf(stderr, "error: tx hex missing from input\n");
                return false;
            }
            char* s = strndup(p, c-p);
            std::string ss = s;
            free(s);
            CAmount a;
            if (!ParseFixedPoint(ss, 8, &a)) {
                fprintf(stderr, "failed to parse amount: %s\n", ss.c_str());
                return false;
            }
            amounts.push_back(a);
            p = c + 1;
            if (*c == ':') break;
        }
    }
    tx = parse_tx(p);
    if (!tx) return false;
    while (amounts.size() < tx->vin.size()) amounts.push_back(0);
    return true;
}

bool Instance::parse_input_transaction(const char* txdata, int select_index) {
    txin = parse_tx(txdata);
    if (!txin) return false;
    if (tx) {
        const uint256& txin_hash = txin->GetHash();
        if (select_index > -1) {
            // verify index is valid
            if (select_index >= tx->vin.size()) {
                fprintf(stderr, "error: the selected index %d is out of bounds (must be less than %zu, the number of inputs in the transaction)\n", select_index, tx->vin.size());
                return false;
            }
            if (txin_hash != tx->vin[select_index].prevout.hash) {
                fprintf(stderr, "error: the selected index (%d) of the transaction refers to txid %s, but the input transaction has txid %s\n", select_index, tx->vin[select_index].prevout.hash.ToString().c_str(), txin_hash.ToString().c_str());
                return false;
            }
            txin_index = select_index;
            txin_vout_index = tx->vin[select_index].prevout.n;
        } else {
            // figure out index from tx vin
            int64_t i = 0;
            for (const auto& input : tx->vin) {
                if (input.prevout.hash == txin_hash) {
                    txin_index = i;
                    txin_vout_index = input.prevout.n;
                    break;
                }
                i++;
            }
            if (txin_index == -1) {
                fprintf(stderr, "error: the input transaction %s is not found in any of the inputs for the provided transaction %s\n", txin_hash.ToString().c_str(), tx->GetHash().ToString().c_str());
                return false;
            }
        }
    }
    return true;
}

bool Instance::parse_script(const char* script_str) {
    std::vector<unsigned char> scriptData = Value(script_str).data_value();
    script = CScript(scriptData.begin(), scriptData.end());
    // for (const auto& keymap : COMPILER_CTX.keymap) {
    //     auto cs = keymap.first.c_str();
    //     auto key = Value(std::vector<uint8_t>(keymap.second.begin(), keymap.second.end())).data;
    //     auto sig = Value((std::string("sig:") + keymap.first).c_str()).data_value();
    //     pretend_valid_map[sig] = key;
    //     pretend_valid_pubkeys.insert(key);
    //     printf("info: provide sig:%s as signature for %s [%s=%s]\n", cs, cs, HexStr(sig).c_str(), HexStr(key).c_str());
    // }
    // try {
    //     msenv = new MSEnv(script, true);
    // } catch (const std::exception& ex) {
    //     printf("miniscript failed to parse script; miniscript support disabled\n");
    //     msenv = nullptr;
    // }
    return script.HasValidOps();
}

bool Instance::parse_script(const std::vector<uint8_t>& script_data) {
    script = CScript(script_data.begin(), script_data.end());
    return script.HasValidOps();
}

bool Instance::parse_pretend_valid_expr(const char* expr) {
    const char* p = expr;
    const char* c = p;
    valtype sig;
    uint160 keyid;
    bool got_sig = false;
    // COMPILER_CTX.symbolic_outputs = true;
    while (*c) {
        while (*c && *c != ',' && *c != ':') ++c;
        char* cs = strndup(p, c-p);
        Value v = Value(cs);
        valtype s = v.data_value();
        free(cs);
        switch (*c) {
        case ':':
            if (got_sig) {
                fprintf(stderr, "parse error (unexpected colon) near %s\n", p);
                return false;
            }
            sig = s;
            got_sig = true;
            break;
        case ',':
        case 0:
            if (!got_sig) {
                fprintf(stderr, "parse error (missing signature) near %s\n", p);
                return false;
            }
            got_sig = false;
            v.do_hash160();
            keyid = uint160(v.data_value());
            // pretend_valid_map[sig] = s;
            pretend_valid_pubkeys.insert(s);
            auto key = CPubKey(ParseHex(p));
            if (!key.IsFullyValid()) {
                fprintf(stderr, "invalid pubkey %s\n", p);
                return false;
            }
            pretend_valid_pubkeys.insert(valtype(key.begin(), key.end()));
            // note: we override below; this may lead to issues
            pretend_valid_map[sig] = valtype(key.begin(), key.end());
            break;
        }
        p = c = c + (*c != 0);
    }
    return true;
}

void Instance::parse_stack_args(const std::vector<const char*> args) {
    for (auto& v : args) {
        auto z = Value(v).data_value();
        stack.push_back(z);
        // if (z.size() == 33) {
        //     // add if valid pubkey
        //     CompilerContext::Key key;
        //     COMPILER_CTX.FromPKBytes(z.begin(), z.end(), key);
        // }
    }
}

void Instance::parse_stack_args(size_t argc, char* const* argv, size_t starting_index) {
    for (int i = starting_index; i < argc; i++) {
        stack.push_back(Value(argv[i]).data_value());
    }
}

bool Instance::setup_environment(unsigned int flags) {
    if (tx) {
        if (txin && txin_index > -1) {
            std::vector<CTxOut> spent_outputs;
            spent_outputs.emplace_back(txin->vout[txin_index]);
            if (tx->vin.size() == 1) {
                txdata.Init(*tx.get(), std::move(spent_outputs));
            }
        }
        checker = new TransactionSignatureChecker(tx.get(), txin_index > -1 ? txin_index : 0, amounts[txin_index > -1 ? txin_index : 0], txdata);
    } else {
        checker = new BaseSignatureChecker();
    }

    execdata.m_codeseparator_pos = 0xFFFFFFFFUL;
    execdata.m_codeseparator_pos_init = true;

    env = new InterpreterEnv(stack, script, flags, *checker, sigver, &error);
    env->successor_script = successor_script;
    env->pretend_valid_map = pretend_valid_map;
    env->pretend_valid_pubkeys = pretend_valid_pubkeys;
    env->done &= successor_script.size() == 0;
    env->execdata = execdata;
    env->tce = tce;

    return env->operational;
}

bool Instance::at_end() { return env->done; }
bool Instance::at_start() { return env->pc == env->script.begin(); }
std::string Instance::error_string() { return exception_string == "" ? ScriptErrorString(*env->serror) : "exception thrown: " + exception_string; }

bool Instance::step(size_t steps) {
    exception_string = "";
    while (steps > 0) {
        if (env->done) return false;
        try {
            if (!StepScript(*env)) return false;
        } catch (const std::exception& ex) {
            exception_string = ex.what();
            return false;
        }
        steps--;
    }
    return true;
}

bool Instance::rewind() {
    if (env->pc == env->script.begin()) {
        return false;
    }
    if (env->done) {
        env->done = false;
    }
    return RewindScript(*env);
}

bool Instance::eval(const size_t argc, char* const* argv) {
    if (argc < 1) return false;
    CScript script;
    for (int i = 0; i < argc; i++) {
        const char* v = argv[i];
        const size_t vlen = strlen(v);
        // empty strings are ignored
        if (!v[0]) continue;
        // number?
        int n = atoi(v);
        if (n != 0) {
            // verify
            char buf[vlen + 1];
            sprintf(buf, "%d", n);
            if (!strcmp(buf, v)) {
                // verified; is it > 3 chars and can it be a hexstring too?
                if (vlen > 3 && !(vlen & 1)) {
                    std::vector<unsigned char> pushData;
                    if (TryHex(v, pushData)) {
                        // it can; warn about using 0x for hex
                        if (VALUE_WARN) btc_logf("warning: ambiguous input %s is interpreted as a numeric value; use 0x%s to force into hexadecimal interpretation\n", v, v);
                    }
                }
                // can it be an opcode too?
                if (n < 16) {
                    if (VALUE_WARN) btc_logf("warning: ambiguous input %s is interpreted as a numeric value (%s), not as an opcode (OP_%s). Use OP_%s to force into op code interpretation\n", v, v, v, v);
                }

                script << (int64_t)n;
                continue;
            }
        }
        // hex string?
        if (!(vlen & 1)) {
            std::vector<unsigned char> pushData;
            if (TryHex(v, pushData)) {
                script << pushData;
                continue;
            }
        }
        opcodetype opc = GetOpCode(v);
        if (opc != OP_INVALIDOPCODE) {
            script << opc;
            continue;
        }
        fprintf(stderr, "error: invalid opcode %s\n", v);
        return false;
    }
    CScript::const_iterator it = script.begin();
    while (it != script.end()) {
        if (!StepScript(*env, it, &script)) {
            fprintf(stderr, "Error: %s\n", ScriptErrorString(*env->serror).c_str());
            return false;
        }
    }
    return true;
}

bool Instance::configure_tx_txin() {
    opcodetype opcode;
    std::vector<uint8_t> pushval;
    // no script and no stack; autogenerate from tx/txin
    // the script is the witness stack, last entry, or scriptpubkey
    // the stack is the witness stack minus last entry, in order, or the results of executing the scriptSig
    amounts[txin_index] = txin->vout[txin_vout_index].nValue;
    btc_logf("input tx index = %" PRId64 "; tx input vout = %" PRId64 "; value = %" PRId64 "\n", txin_index, txin_vout_index, amounts[txin_index]);
    auto& scriptSig = tx->vin[txin_index].scriptSig;
    CScript scriptPubKey = txin->vout[txin_vout_index].scriptPubKey;
    std::vector<const char*> push_del;

    // legacy
    sigver = SigVersion::BASE;
    script = scriptSig;
    successor_script = scriptPubKey;

    parse_stack_args(push_del);
    while (!push_del.empty()) {
        delete push_del.back();
        push_del.pop_back();
    }

    // // extract pubkeys from script
    // CScript::const_iterator it = script.begin();
    // while (script.GetOp(it, opcode, pushval)) {
    //     if (pushval.size() == 33) {
    //         // add if valid pubkey
    //         CompilerContext::Key key;
    //         COMPILER_CTX.FromPKBytes(pushval.begin(), pushval.end(), key);
    //     }
    // }

    // try {
    //     msenv = new MSEnv(successor_script, true);
    // } catch (const std::exception& ex) {
    //     printf("miniscript failed to parse script; miniscript support disabled\n");
    //     msenv = nullptr;
    // }

    return true;
}

uint256 Instance::calc_sighash() {
    uint256 hash;
    std::vector<CTxOut> spent_outputs;
    spent_outputs.emplace_back(txin->vout[txin_vout_index]);
    txdata = PrecomputedTransactionData();
    txdata.Init(*tx.get(), std::move(spent_outputs));
    if (sigver == SigVersion::BASE) sigver = SigVersion::TAPROOT;
    // bool ret = SignatureHashSchnorr(sighash, execdata, *txTo, nIn, hashtype, sigversion, this->txdata);
    if (!SignatureHashSchnorr(hash, execdata, *tx, txin_index, 0x00, sigver, txdata)) {
        fprintf(stderr, "Failed to generate schnorr signature hash!\n");
        exit(1);
    }
    return hash;
}
