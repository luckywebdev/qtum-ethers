const TX_OVERHEAD_NVERSION = 4;
const TX_OVERHEAD_INPUT_COUNT = 1;
const TX_OVERHEAD_OUTPUT_COUNT = 1;
const TX_OVERHEAD_NLOCKTIME = 4;
const TX_INPUT_OUTPOINT = 36;
// up to 3 bytes for script sig for maximum length of 10000
const TX_INPUT_SCRIPTSIGLENGTH = 1;
const TX_INPUT_NSEQUENCE = 4;
const TX_OUTPUT_NVALUE = 8;
const TX_OUTPUT_SCRIPTPUBKEYLENGTH = 1;
export const GLOBAL_VARS = {
    TX_OVERHEAD_BASE: TX_OVERHEAD_NVERSION + TX_OVERHEAD_INPUT_COUNT + TX_OVERHEAD_OUTPUT_COUNT + TX_OVERHEAD_NLOCKTIME,
    TX_OVERHEAD_NVERSION: TX_OVERHEAD_NVERSION,
    TX_OVERHEAD_INPUT_COUNT: TX_OVERHEAD_INPUT_COUNT,
    TX_INPUT_BASE: TX_INPUT_OUTPOINT + TX_INPUT_SCRIPTSIGLENGTH + TX_INPUT_NSEQUENCE,
    TX_INPUT_OUTPOINT: TX_INPUT_OUTPOINT,
    TX_INPUT_SCRIPTSIGLENGTH: TX_INPUT_SCRIPTSIGLENGTH,
    TX_INPUT_NSEQUENCE: TX_INPUT_NSEQUENCE,
    TX_OVERHEAD_OUTPUT_COUNT: TX_OVERHEAD_OUTPUT_COUNT,
    TX_INPUT_SCRIPTSIG_P2PK: 72,
    TX_INPUT_SCRIPTSIG_P2PKH: 107,
    TX_INPUT_SCRIPTSIG_P2SH2OF3: 254,
    TX_OUTPUT_BASE: TX_OUTPUT_NVALUE + TX_OUTPUT_SCRIPTPUBKEYLENGTH,
    TX_OUTPUT_NVALUE: TX_OUTPUT_NVALUE,
    TX_OUTPUT_SCRIPTPUBKEYLENGTH: TX_OUTPUT_SCRIPTPUBKEYLENGTH,
    TX_OVERHEAD_NLOCKTIME: TX_OVERHEAD_NLOCKTIME,
    // Output scripts
    // OP_DUP OP_HASH160 OP_PUSH20 <public_key_hash> OP_EQUALVERIFY OP_CHECKSIG
    TX_OUTPUT_SCRIPTPUBKEY_P2PKH: 25,
    // OP_0 OP_PUSH20 <public_key_hash>
    TX_OUTPUT_SCRIPTPUBKEY_P2WPKH: 22,
    // OP_HASH160 OP_PUSH20 <script_hash> OP_EQUAL
    TX_OUTPUT_SCRIPTPUBKEY_P2SH2OF3: 23,
    // OP_0 OP_PUSH32 <script_hash>
    TX_OUTPUT_SCRIPTPUBKEY_P2WSH2OF3: 34,
    // OP_1 OP_PUSH32 <schnorr_public_key>
    TX_OUTPUT_SCRIPTPUBKEY_P2TR: 34,
    HASH_TYPE: 0x01,
    MAX_FEE_RATE: 0.4,
    AVG_FEE_RATE: 0.002,
    // transaction types
    CONTRACT_CALL: 1,
    CONTRACT_CREATION: 2,
    P2PKH: 3,
    DEPLOY_ERROR: 4,
    // vsize witness scale
    WITNESS_SCALE_FACTOR: 4,
    UTXO_VINDEX: 0
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZ2xvYmFsLXZhcnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2hlbHBlcnMvZ2xvYmFsLXZhcnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTSxvQkFBb0IsR0FBRyxDQUFDLENBQUM7QUFDL0IsTUFBTSx1QkFBdUIsR0FBRyxDQUFDLENBQUM7QUFDbEMsTUFBTSx3QkFBd0IsR0FBRyxDQUFDLENBQUM7QUFDbkMsTUFBTSxxQkFBcUIsR0FBRyxDQUFDLENBQUM7QUFDaEMsTUFBTSxpQkFBaUIsR0FBRyxFQUFFLENBQUM7QUFDN0IsMkRBQTJEO0FBQzNELE1BQU0sd0JBQXdCLEdBQUcsQ0FBQyxDQUFDO0FBQ25DLE1BQU0sa0JBQWtCLEdBQUcsQ0FBQyxDQUFDO0FBQzdCLE1BQU0sZ0JBQWdCLEdBQUcsQ0FBQyxDQUFDO0FBQzNCLE1BQU0sNEJBQTRCLEdBQUcsQ0FBQyxDQUFDO0FBRXZDLE1BQU0sQ0FBQyxNQUFNLFdBQVcsR0FBRztJQUN2QixnQkFBZ0IsRUFBRSxvQkFBb0IsR0FBRyx1QkFBdUIsR0FBRyx3QkFBd0IsR0FBRyxxQkFBcUI7SUFDbkgsb0JBQW9CLEVBQUUsb0JBQW9CO0lBQzFDLHVCQUF1QixFQUFFLHVCQUF1QjtJQUVoRCxhQUFhLEVBQUUsaUJBQWlCLEdBQUcsd0JBQXdCLEdBQUcsa0JBQWtCO0lBQ2hGLGlCQUFpQixFQUFFLGlCQUFpQjtJQUNwQyx3QkFBd0IsRUFBRSx3QkFBd0I7SUFDbEQsa0JBQWtCLEVBQUUsa0JBQWtCO0lBRXRDLHdCQUF3QixFQUFFLHdCQUF3QjtJQUVsRCx1QkFBdUIsRUFBRSxFQUFFO0lBQzNCLHdCQUF3QixFQUFFLEdBQUc7SUFDN0IsMkJBQTJCLEVBQUUsR0FBRztJQUVoQyxjQUFjLEVBQUUsZ0JBQWdCLEdBQUcsNEJBQTRCO0lBQy9ELGdCQUFnQixFQUFFLGdCQUFnQjtJQUNsQyw0QkFBNEIsRUFBRSw0QkFBNEI7SUFFMUQscUJBQXFCLEVBQUUscUJBQXFCO0lBRTVDLGlCQUFpQjtJQUNqQiwyRUFBMkU7SUFDM0UsNEJBQTRCLEVBQUUsRUFBRTtJQUNoQyxtQ0FBbUM7SUFDbkMsNkJBQTZCLEVBQUUsRUFBRTtJQUNqQyw4Q0FBOEM7SUFDOUMsK0JBQStCLEVBQUUsRUFBRTtJQUNuQywrQkFBK0I7SUFDL0IsZ0NBQWdDLEVBQUUsRUFBRTtJQUNwQyxzQ0FBc0M7SUFDdEMsMkJBQTJCLEVBQUUsRUFBRTtJQUUvQixTQUFTLEVBQUUsSUFBSTtJQUNmLFlBQVksRUFBRSxHQUFHO0lBQ2pCLFlBQVksRUFBRSxLQUFLO0lBQ25CLG9CQUFvQjtJQUNwQixhQUFhLEVBQUUsQ0FBQztJQUNoQixpQkFBaUIsRUFBRSxDQUFDO0lBQ3BCLEtBQUssRUFBRSxDQUFDO0lBQ1IsWUFBWSxFQUFFLENBQUM7SUFDZixzQkFBc0I7SUFDdEIsb0JBQW9CLEVBQUUsQ0FBQztJQUN2QixXQUFXLEVBQUUsQ0FBQztDQUNmLENBQUEifQ==