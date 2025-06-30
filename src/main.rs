use base64::{Engine as _, engine::general_purpose};
use bs58;
use poem::{
    IntoResponse, Response, Route, Server, get, handler, http::StatusCode, listener::TcpListener,
    post, web::Json,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature},
    signer::Signer,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::{initialize_mint, mint_to, transfer};
use std::str::FromStr;

#[derive(Serialize, Deserialize)]
struct KeyPairData {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize)]
struct GenerateKeyPairOutput {
    pub success: bool,
    pub data: KeyPairData,
}

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Debug, Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Debug, Serialize)]
struct CreateTokenResponse {
    success: bool,
    data: TokenInstructionData,
}

#[derive(Debug, Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: Vec<AccountMetaSerializable>,
    instruction_data: String,
}

#[derive(Debug, Serialize)]
struct AccountMetaSerializable {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    success: bool,
    data: SignMessageResponseData,
}

#[derive(Serialize)]
struct SignMessageResponseData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    success: bool,
    data: VerifyMessageResponseData,
}

#[derive(Serialize)]
struct VerifyMessageResponseData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Debug, Serialize)]
struct SendSolResponse {
    success: bool,
    data: SolInstructionData,
}

#[derive(Debug, Serialize)]
struct SolInstructionData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: TokenTransferInstructionData,
}

#[derive(Debug, Serialize)]
struct TokenTransferInstructionData {
    program_id: String,
    accounts: Vec<TokenAccountMeta>,
    instruction_data: String,
}

#[derive(Debug, Serialize)]
struct TokenAccountMeta {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[handler]
async fn create_token(Json(payload): Json<CreateTokenRequest>) -> Response {
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority,
        None,
        payload.decimals,
    ) {
        Ok(ix) => ix,
        Err(_e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaSerializable {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn mint_token(Json(payload): Json<MintTokenRequest>) -> Response {
    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Description of error".to_string(),
                }),
            )
                .into_response();
        }
    };

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Description of error".to_string(),
                }),
            )
                .into_response();
        }
    };

    let authority_pubkey = match Pubkey::from_str(&payload.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Description of error".to_string(),
                }),
            )
                .into_response();
        }
    };

    let ix = match mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[&authority_pubkey],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: "Description of error".to_string(),
                }),
            )
                .into_response();
        }
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| AccountMetaSerializable {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect();

    let response = CreateTokenResponse {
        success: true,
        data: TokenInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn sign_message(Json(payload): Json<SignMessageRequest>) -> Response {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        )
            .into_response();
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let keypair = match Keypair::try_from(secret_bytes.as_slice()) {
        Ok(kp) => kp,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let signature = keypair.sign_message(payload.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());

    let response = SignMessageResponse {
        success: true,
        data: SignMessageResponseData {
            signature: signature_b64,
            public_key: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            message: payload.message,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn verify_message(Json(payload): Json<VerifyMessageRequest>) -> Response {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        )
            .into_response();
    }

    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let signature = match Signature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let valid = signature.verify(pubkey.as_ref(), payload.message.as_bytes());

    let response = VerifyMessageResponse {
        success: true,
        data: VerifyMessageResponseData {
            valid,
            message: payload.message,
            pubkey: bs58::encode(pubkey.to_bytes()).into_string(),
        },
    };

    Json(response).into_response()
}

#[handler]
async fn send_sol(Json(payload): Json<SendSolRequest>) -> Response {
    if payload.from.is_empty() || payload.to.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        )
            .into_response();
    }
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);
    let instruction_data = general_purpose::STANDARD.encode(&ix.data);

    let response = SendSolResponse {
        success: true,
        data: SolInstructionData {
            program_id: ix.program_id.to_string(),
            accounts: vec![from_pubkey.to_string(), to_pubkey.to_string()],
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
async fn send_token(Json(payload): Json<SendTokenRequest>) -> Response {
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        )
            .into_response();
    }

    let destination_pubkey = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let mint_pubkey = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let owner_pubkey = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let source_pubkey = get_associated_token_address(&owner_pubkey, &mint_pubkey);

    let ix = match transfer(
        &spl_token::id(),
        &source_pubkey,
        &destination_pubkey,
        &owner_pubkey,
        &[&owner_pubkey],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    success: false,
                    error: String::from("Description of error"),
                }),
            )
                .into_response();
        }
    };

    let instruction_data = general_purpose::STANDARD.encode(&ix.data);
    let accounts = ix
        .accounts
        .into_iter()
        .map(|meta| TokenAccountMeta {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
        })
        .collect();

    let response = SendTokenResponse {
        success: true,
        data: TokenTransferInstructionData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    };

    Json(response).into_response()
}

#[handler]
fn generate_keypair() -> Json<GenerateKeyPairOutput> {
    let keypair = Keypair::new();
    let response = GenerateKeyPairOutput {
        success: true,
        data: KeyPairData {
            pubkey: bs58::encode(keypair.pubkey().to_bytes()).into_string(),
            secret: bs58::encode(keypair.secret_bytes()).into_string(),
        },
    };
    Json(response)
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token));

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
