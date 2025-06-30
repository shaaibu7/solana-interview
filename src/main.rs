use actix_web::{web, App, HttpResponse, HttpServer, Result, middleware::Logger};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

// Response wrapper types
#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

// Request/Response structs
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
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

#[derive(Serialize)]
struct SignMessageData {
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
struct VerifyMessageData {
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

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountMeta>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SolTransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenTransferAccount>,
    instruction_data: String,
}

// Utility functions
fn generate_mock_pubkey() -> String {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    bs58::encode(verifying_key.as_bytes()).into_string()
}

fn base58_to_bytes(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    bs58::decode(s).into_vec().map_err(|e| e.into())
}

fn bytes_to_base58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

fn create_error_response(error: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(ErrorResponse {
        success: false,
        error: error.to_string(),
    })
}

// Endpoint handlers
async fn generate_keypair() -> Result<HttpResponse> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    let pubkey = bytes_to_base58(verifying_key.as_bytes());
    let secret = bytes_to_base58(&signing_key.to_bytes());
    
    let response = SuccessResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    };
    
    Ok(HttpResponse::Ok().json(response))
}

async fn create_token(payload: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    // Validate input
    if payload.mint_authority.is_empty() || payload.mint.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    // Validate base58 addresses
    if base58_to_bytes(&payload.mint_authority).is_err() || base58_to_bytes(&payload.mint).is_err() {
        return Ok(create_error_response("Invalid base58 address"));
    }

    // Mock SPL Token program ID
    let program_id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
    
    // Mock instruction data for InitializeMint
    let mock_instruction_data = general_purpose::STANDARD.encode(b"mock_initialize_mint_instruction");
    
    let accounts = vec![
        AccountMeta {
            pubkey: payload.mint.clone(),
            is_signer: false,
            is_writable: true,
        },
        AccountMeta {
            pubkey: "SysvarRent111111111111111111111111111111111".to_string(),
            is_signer: false,
            is_writable: false,
        },
    ];

    let response = SuccessResponse {
        success: true,
        data: InstructionData {
            program_id,
            accounts,
            instruction_data: mock_instruction_data,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn mint_token(payload: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    // Validate input
    if payload.mint.is_empty() || payload.destination.is_empty() || payload.authority.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    // Validate addresses
    if base58_to_bytes(&payload.mint).is_err() 
        || base58_to_bytes(&payload.destination).is_err() 
        || base58_to_bytes(&payload.authority).is_err() {
        return Ok(create_error_response("Invalid base58 address"));
    }

    let program_id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
    let mock_instruction_data = general_purpose::STANDARD.encode(
        format!("mint_to_{}", payload.amount).as_bytes()
    );

    let accounts = vec![
        AccountMeta {
            pubkey: payload.mint.clone(),
            is_signer: false,
            is_writable: true,
        },
        AccountMeta {
            pubkey: payload.destination.clone(),
            is_signer: false,
            is_writable: true,
        },
        AccountMeta {
            pubkey: payload.authority.clone(),
            is_signer: true,
            is_writable: false,
        },
    ];

    let response = SuccessResponse {
        success: true,
        data: InstructionData {
            program_id,
            accounts,
            instruction_data: mock_instruction_data,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}


async fn verify_message(payload: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    let is_valid = match verify_signature(&payload.message, &payload.signature, &payload.pubkey) {
        Ok(valid) => valid,
        Err(_) => false,
    };

    let response = SuccessResponse {
        success: true,
        data: VerifyMessageData {
            valid: is_valid,
            message: payload.message.clone(),
            pubkey: payload.pubkey.clone(),
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

fn verify_signature(message: &str, signature_b64: &str, pubkey_b58: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let signature_bytes = general_purpose::STANDARD.decode(signature_b64)?;
    let pubkey_bytes = base58_to_bytes(pubkey_b58)?;
    
    if pubkey_bytes.len() != 32 || signature_bytes.len() != 64 {
        return Ok(false);
    }

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap())?;
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

async fn sign_message(payload: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Ok(create_error_response("Missing required fields"));
    }

    // Decode the secret key
    let secret_bytes = match base58_to_bytes(&payload.secret) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(create_error_response("Invalid secret key format")),
    };

    if secret_bytes.len() != 32 {
        return Ok(create_error_response("Invalid secret key length"));
    }

    let signing_key = SigningKey::from_bytes(&secret_bytes.try_into().unwrap());
        

    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(payload.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key_b58 = bytes_to_base58(verifying_key.as_bytes());

    let response = SuccessResponse {
        success: true,
        data: SignMessageData {
            signature: signature_b64,
            public_key: public_key_b58,
            message: payload.message.clone(),
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn send_sol(payload: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    // Validate input
    if payload.from.is_empty() || payload.to.is_empty() || payload.lamports == 0 {
        return Ok(create_error_response("Invalid input: missing fields or zero lamports"));
    }

    // Validate addresses
    if base58_to_bytes(&payload.from).is_err() || base58_to_bytes(&payload.to).is_err() {
        return Ok(create_error_response("Invalid base58 address"));
    }

    // Check for same address
    if payload.from == payload.to {
        return Ok(create_error_response("Cannot transfer to the same address"));
    }

    let program_id = "11111111111111111111111111111111".to_string(); // System Program
    let mock_instruction_data = general_purpose::STANDARD.encode(
        format!("transfer_{}_lamports", payload.lamports).as_bytes()
    );

    let response = SuccessResponse {
        success: true,
        data: SolTransferData {
            program_id,
            accounts: vec![payload.from.clone(), payload.to.clone()],
            instruction_data: mock_instruction_data,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

async fn send_token(payload: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    // Validate input
    if payload.destination.is_empty() || payload.mint.is_empty() || payload.owner.is_empty() || payload.amount == 0 {
        return Ok(create_error_response("Invalid input: missing fields or zero amount"));
    }

    // Validate addresses
    if base58_to_bytes(&payload.destination).is_err() 
        || base58_to_bytes(&payload.mint).is_err() 
        || base58_to_bytes(&payload.owner).is_err() {
        return Ok(create_error_response("Invalid base58 address"));
    }

    let program_id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string();
    let mock_instruction_data = general_purpose::STANDARD.encode(
        format!("transfer_{}_tokens", payload.amount).as_bytes()
    );

    // Mock source token account (derived from owner + mint)
    let source_token_account = generate_mock_pubkey();

    let accounts = vec![
        TokenTransferAccount {
            pubkey: source_token_account,
            is_signer: false,
        },
        TokenTransferAccount {
            pubkey: payload.destination.clone(),
            is_signer: false,
        },
        TokenTransferAccount {
            pubkey: payload.owner.clone(),
            is_signer: true,
        },
    ];

    let response = SuccessResponse {
        success: true,
        data: TokenTransferData {
            program_id,
            accounts,
            instruction_data: mock_instruction_data,
        },
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("Server running on http://0.0.0.0:3000");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}



