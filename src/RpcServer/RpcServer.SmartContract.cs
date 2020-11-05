#pragma warning disable IDE0051
#pragma warning disable IDE0060

using Neo.Cryptography.ECC;
using Neo.IO;
using Neo.IO.Json;
using Neo.Ledger;
using Neo.Network.P2P.Payloads;
using Neo.Persistence;
using Neo.SmartContract;
using Neo.SmartContract.Native;
using Neo.VM;
using Neo.Wallets;
using System;
using System.IO;
using System.Linq;

namespace Neo.Plugins
{
    partial class RpcServer
    {
        private class Signers : IVerifiable
        {
            private readonly Signer[] _signers;
            public Witness[] Witnesses { get; set; }
            public int Size => _signers.Length;

            public Signers(Signer[] signers)
            {
                _signers = signers;
            }

            public void Serialize(BinaryWriter writer)
            {
                throw new NotImplementedException();
            }

            public void Deserialize(BinaryReader reader)
            {
                throw new NotImplementedException();
            }

            public void DeserializeUnsigned(BinaryReader reader)
            {
                throw new NotImplementedException();
            }

            public UInt160[] GetScriptHashesForVerifying(StoreView snapshot)
            {
                return _signers.Select(p => p.Account).ToArray();
            }

            public Signer[] GetSigners()
            {
                return _signers;
            }

            public void SerializeUnsigned(BinaryWriter writer)
            {
                throw new NotImplementedException();
            }
        }

        private JObject GetInvokeResult(byte[] script, Signers signers = null)
        {
            using ApplicationEngine engine = ApplicationEngine.Run(script, container: signers, gas: settings.MaxGasInvoke);
            JObject json = new JObject();
            json["script"] = Convert.ToBase64String(script);
            json["state"] = engine.State;
            json["gasconsumed"] = engine.GasConsumed.ToString();
            json["exception"] = GetExceptionMessage(engine.FaultException);
            try
            {
                json["stack"] = new JArray(engine.ResultStack.Select(p => p.ToJson()));
            }
            catch (InvalidOperationException)
            {
                json["stack"] = "error: recursive reference";
            }
            if (engine.State != VMState.FAULT)
            {
                ProcessInvokeWithWallet(json, signers);
            }
            return json;
        }

        private JObject GetVerificationResult(StoreView snapshot, []byte script, UInt160 script_hash, Witness witness, Signers signers = null)
        {
            if (!TryCreateVerifyEngine(signers, snapshot, script_hash, witness, settings.MaxGasInvoke, out var engine))
            {
                 throw new RpcException(-300, "Cannot create verification engine");
            }
            JObject json = new JObject();
            using(engine)
            {
                json["script"] = Convert.ToBase64String(script);
                json["state"] = engine.Execute();
                json["gasconsumed"] = engine.GasConsumed.ToString();
                json["exception"] = GetExceptionMessage(engine.FaultException);
                try
                {
                    json["stack"] = new JArray(engine.ResultStack.Select(p => p.ToJson()));
                }
                catch (InvalidOperationException)
                {
                    json["stack"] = "error: recursive reference";
                }
            }
            return json;
        }

        private static Signers SignersFromJson(JArray _params)
        {
            var ret = new Signers(_params.Select(u => new Signer()
            {
                Account = AddressToScriptHash(u["account"].AsString()),
                Scopes = (WitnessScope)Enum.Parse(typeof(WitnessScope), u["scopes"]?.AsString()),
                AllowedContracts = ((JArray)u["allowedcontracts"])?.Select(p => UInt160.Parse(p.AsString())).ToArray(),
                AllowedGroups = ((JArray)u["allowedgroups"])?.Select(p => ECPoint.Parse(p.AsString(), ECCurve.Secp256r1)).ToArray()
            }).ToArray());

            // Validate format

            _ = IO.Helper.ToByteArray(ret.GetSigners()).AsSerializableArray<Signer>();

            return ret;
        }

        [RpcMethod]
        protected virtual JObject InvokeFunction(JArray _params)
        {
            UInt160 script_hash = UInt160.Parse(_params[0].AsString());
            string operation = _params[1].AsString();
            ContractParameter[] args = _params.Count >= 3 ? ((JArray)_params[2]).Select(p => ContractParameter.FromJson(p)).ToArray() : new ContractParameter[0];
            Signers signers = _params.Count >= 4 ? SignersFromJson((JArray)_params[3]) : null;

            if (operation == "verify")
            {
                byte[] invocationScript;
                using (ScriptBuilder sb = new ScriptBuilder())
                {
                    invocationScript = sb.EmitPush(args).ToArray();
                }
                var snapshot = Blockchain.Singleton.GetSnapshot();
                var contract = snapshot.Contracts.TryGet(script_hash);
                return GetVerificationResult(snapshot, contract.Script, script_hash, new Witness{ InvocationScript = invocationScript }, signers);
            }

            byte[] script;
            using (ScriptBuilder sb = new ScriptBuilder())
            {
                script = sb.EmitAppCall(script_hash, operation, args).ToArray();
            }
            return GetInvokeResult(script, signers);
        }

        [RpcMethod]
        protected virtual JObject InvokeScript(JArray _params)
        {
            byte[] script = Convert.FromBase64String(_params[0].AsString());
            Signers signers = _params.Count >= 2 ? SignersFromJson((JArray)_params[1]) : null;
            return GetInvokeResult(script, signers);
        }

        [RpcMethod]
        protected virtual JObject InvokeScriptVerify(JArray _params)
        {
            byte[] invocationScript = Convert.FromBase64String(_params[0].AsString());
            byte[] verificationScript = Convert.FromBase64String(_params[1].AsString());
            Signers signers = _params.Count >= 3 ? SignersFromJson((JArray)_params[2]) : null;
            var snapshot = Blockchain.Singleton.GetSnapshot();
            return GetVerificationResult(snapshot, invocationScript, null, new Witness
                {
                    InvocationScript = invocationScript,
                    VerificationScript = verificationScript
                }, signers);
        }

        [RpcMethod]
        protected virtual JObject GetUnclaimedGas(JArray _params)
        {
            string address = _params[0].AsString();
            JObject json = new JObject();
            UInt160 script_hash;
            try
            {
                script_hash = AddressToScriptHash(address);
            }
            catch
            {
                script_hash = null;
            }
            if (script_hash == null)
                throw new RpcException(-100, "Invalid address");
            SnapshotView snapshot = Blockchain.Singleton.GetSnapshot();
            json["unclaimed"] = NativeContract.NEO.UnclaimedGas(snapshot, script_hash, snapshot.Height + 1).ToString();
            json["address"] = script_hash.ToAddress();
            return json;
        }

        static string GetExceptionMessage(Exception exception)
        {
            if (exception == null) return null;

            if (exception.InnerException != null)
            {
                return exception.InnerException.Message;
            }

            return exception.Message;
        }
    }
}
