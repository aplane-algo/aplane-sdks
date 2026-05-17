import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import { SignerClient, createApsignerAccount } from "aplane";

const sender = process.env.APLANE_ADDRESS;
if (!sender) throw new Error("APLANE_ADDRESS is required");

const algorand = AlgorandClient.testNet();
const signer = await SignerClient.fromEnv();

try {
  const info = await algorand.account.getInformation(sender);
  const account = createApsignerAccount({
    client: signer,
    address: sender,
    authAddress: info.authAddr?.toString() ?? sender,
  });
  const txn = await algorand.createTransaction.payment({
    sender,
    signer: account,
    receiver: sender,
    amount: microAlgo(0),
    validityWindow: 1000,
  });
  const signed = await account.signer([txn], [0]);
  console.log((await algorand.client.algod.sendRawTransaction(signed)).txId);
} finally {
  signer.close();
}
