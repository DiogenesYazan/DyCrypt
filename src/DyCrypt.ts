import crypto from 'node:crypto';
import type { EncryptedData } from './types.js';

/**
 * Classe DyCrypt: Implementa criptografia em cascata de alta segurança
 * 
 * Arquitetura de Segurança:
 * ========================
 * Esta classe implementa "Cascading Encryption" (criptografia em cascata), uma técnica de
 * defesa em profundidade onde os dados passam por múltiplas camadas de criptografia usando
 * algoritmos diferentes. Isso protege contra:
 * 
 * 1. Vulnerabilidades futuras em um único algoritmo (se AES for quebrado, ChaCha20 ainda protege)
 * 2. Ataques de força bruta (atacante precisa quebrar AMBOS os algoritmos)
 * 3. Side-channel attacks específicos de um algoritmo
 * 
 * Camadas:
 * --------
 * Camada 1: AES-256-GCM (Advanced Encryption Standard)
 *   - Algoritmo: Padrão NIST, amplamente auditado e confiável
 *   - Modo: GCM (Galois/Counter Mode) fornece AEAD (Authenticated Encryption with Associated Data)
 *   - Vantagens: Suporte de hardware (AES-NI), extremamente rápido, resistente a padding oracle
 *   - Auth Tag: Protege contra modificação dos dados (integridade criptográfica)
 * 
 * Camada 2: ChaCha20-Poly1305
 *   - Algoritmo: Design moderno por Daniel J. Bernstein
 *   - Modo: Poly1305 fornece autenticação (também AEAD)
 *   - Vantagens: Resistente a timing attacks, excelente performance em software
 *   - Uso: Padrão do TLS 1.3 e WireGuard
 * 
 * Derivação de Chaves:
 * -------------------
 * - Função: scrypt (preferível ao pbkdf2)
 * - Razão: scrypt é memory-hard, tornando ataques de GPU/ASIC muito mais caros
 * - Parâmetros: N=2^14 (custo CPU), r=8 (tamanho de bloco), p=1 (paralelismo)
 * - Salts únicos: Cada camada usa um salt diferente para gerar chaves independentes
 */
export class DyCrypt {
  private masterPassword: Buffer;
  
  /**
   * Parâmetros do scrypt (memory-hard key derivation function)
   * N=16384 (2^14): Custo de CPU/memória - aumentar para mais segurança (mas mais lento)
   * r=8: Tamanho do bloco interno
   * p=1: Paralelismo (1 = sequencial)
   */
  private readonly scryptParams = {
    N: 16384,
    r: 8,
    p: 1,
    keyLength: 32, // 256 bits para AES-256 e ChaCha20
    saltLength: 16, // 128 bits de entropia
  };

  /**
   * Cria uma instância do DyCrypt
   * @param masterPassword Senha mestra para derivar todas as chaves de criptografia
   */
  constructor(masterPassword: string) {
    // Armazenar como Buffer para evitar problemas de encoding
    this.masterPassword = Buffer.from(masterPassword, 'utf-8');
  }

  /**
   * Deriva uma chave criptográfica usando scrypt (Key Derivation Function)
   * 
   * Por que scrypt ao invés de pbkdf2?
   * ----------------------------------
   * scrypt é "memory-hard", significa que requer muita RAM para computar,
   * tornando ataques de força bruta com GPUs/ASICs extremamente caros.
   * pbkdf2 é apenas "CPU-hard" e pode ser acelerado com hardware especializado.
   * 
   * @param salt Salt criptográfico único (deve ser diferente para cada chave)
   * @returns Chave de 256 bits derivada criptograficamente
   */
  private async _deriveKey(salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.scrypt(
        this.masterPassword,
        salt,
        this.scryptParams.keyLength,
        {
          N: this.scryptParams.N,
          r: this.scryptParams.r,
          p: this.scryptParams.p,
        },
        (err, derivedKey) => {
          if (err) reject(err);
          else resolve(derivedKey);
        }
      );
    });
  }

  /**
   * Criptografa dados usando cascata de dois algoritmos (AES-256-GCM → ChaCha20-Poly1305)
   * 
   * Fluxo de Criptografia:
   * ----------------------
   * 1. Gera salts criptográficos únicos para cada camada (evita key reuse)
   * 2. Deriva chaves independentes usando scrypt
   * 3. CAMADA 1: Criptografa com AES-256-GCM (+ auth tag para integridade)
   * 4. CAMADA 2: Criptografa o resultado da camada 1 com ChaCha20-Poly1305
   * 5. Retorna JSON com todos os metadados necessários para descriptografia
   * 
   * @param data Dados em texto plano para criptografar
   * @returns Objeto contendo salts, IVs, auth tags e ciphertext
   */
  async encrypt(data: string): Promise<EncryptedData> {
    // ============================================
    // CAMADA 1: AES-256-GCM
    // ============================================
    
    // Gera salt único para esta camada
    const salt1 = crypto.randomBytes(this.scryptParams.saltLength);
    
    // Deriva chave de 256 bits usando scrypt
    const key1 = await this._deriveKey(salt1);
    
    // GCM requer IV de 12 bytes (96 bits) para máxima segurança
    const iv1 = crypto.randomBytes(12);
    
    // Cria cipher AES-256-GCM
    const cipher1 = crypto.createCipheriv('aes-256-gcm', key1, iv1);
    
    // Criptografa os dados
    let encrypted1 = cipher1.update(data, 'utf-8');
    encrypted1 = Buffer.concat([encrypted1, cipher1.final()]);
    
    // Obtém authentication tag (AEAD) - garante integridade e autenticidade
    const authTag1 = cipher1.getAuthTag();

    // ============================================
    // CAMADA 2: ChaCha20-Poly1305
    // ============================================
    
    // Salt único e independente para a segunda camada
    const salt2 = crypto.randomBytes(this.scryptParams.saltLength);
    
    // Deriva chave completamente diferente da primeira
    const key2 = await this._deriveKey(salt2);
    
    // ChaCha20-Poly1305 também usa IV de 12 bytes
    const iv2 = crypto.randomBytes(12);
    
    // Cria cipher ChaCha20-Poly1305
    const cipher2 = crypto.createCipheriv('chacha20-poly1305', key2, iv2, {
      authTagLength: 16, // Poly1305 auth tag de 128 bits
    });
    
    // Criptografa o resultado da primeira camada
    let encrypted2 = cipher2.update(encrypted1);
    encrypted2 = Buffer.concat([encrypted2, cipher2.final()]);
    
    // Obtém authentication tag da segunda camada
    const authTag2 = cipher2.getAuthTag();

    // Retorna estrutura JSON com todos os componentes necessários para decrypt
    return {
      salt1: salt1.toString('base64'),
      salt2: salt2.toString('base64'),
      iv1: iv1.toString('base64'),
      iv2: iv2.toString('base64'),
      authTag1: authTag1.toString('base64'),
      authTag2: authTag2.toString('base64'),
      ciphertext: encrypted2.toString('base64'),
    };
  }

  /**
   * Descriptografa dados que foram criptografados pelo método encrypt()
   * 
   * Fluxo de Descriptografia:
   * ------------------------
   * O processo é o inverso exato da criptografia:
   * 1. Reconstrói os Buffers a partir do JSON base64
   * 2. Deriva as mesmas chaves usando os salts originais
   * 3. CAMADA 2: Descriptografa com ChaCha20-Poly1305 (verifica auth tag)
   * 4. CAMADA 1: Descriptografa com AES-256-GCM (verifica auth tag)
   * 5. Retorna os dados em texto plano
   * 
   * Segurança:
   * ----------
   * Se qualquer auth tag estiver incorreto (dados foram modificados), a
   * descriptografia falha com erro. Isso garante integridade criptográfica.
   * 
   * @param encryptedData Objeto retornado pelo método encrypt()
   * @returns Dados em texto plano original
   * @throws Error se auth tags forem inválidos (dados foram adulterados)
   */
  async decrypt(encryptedData: EncryptedData): Promise<string> {
    // Reconstrói os Buffers a partir dos strings base64
    const salt1 = Buffer.from(encryptedData.salt1, 'base64');
    const salt2 = Buffer.from(encryptedData.salt2, 'base64');
    const iv1 = Buffer.from(encryptedData.iv1, 'base64');
    const iv2 = Buffer.from(encryptedData.iv2, 'base64');
    const authTag1 = Buffer.from(encryptedData.authTag1, 'base64');
    const authTag2 = Buffer.from(encryptedData.authTag2, 'base64');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');

    // ============================================
    // CAMADA 2: ChaCha20-Poly1305 (reverter primeiro)
    // ============================================
    
    // Deriva a mesma chave usando o salt original
    const key2 = await this._deriveKey(salt2);
    
    // Cria decipher ChaCha20-Poly1305
    const decipher2 = crypto.createDecipheriv('chacha20-poly1305', key2, iv2, {
      authTagLength: 16,
    });
    
    // Define o auth tag (CRÍTICO: verifica integridade dos dados)
    decipher2.setAuthTag(authTag2);
    
    // Descriptografa - se auth tag for inválido, lança erro aqui
    let decrypted2 = decipher2.update(ciphertext);
    decrypted2 = Buffer.concat([decrypted2, decipher2.final()]);

    // ============================================
    // CAMADA 1: AES-256-GCM
    // ============================================
    
    // Deriva a mesma chave usando o salt original
    const key1 = await this._deriveKey(salt1);
    
    // Cria decipher AES-256-GCM
    const decipher1 = crypto.createDecipheriv('aes-256-gcm', key1, iv1);
    
    // Define o auth tag
    decipher1.setAuthTag(authTag1);
    
    // Descriptografa - se auth tag for inválido, lança erro aqui
    let decrypted1 = decipher1.update(decrypted2);
    decrypted1 = Buffer.concat([decrypted1, decipher1.final()]);

    // Retorna texto plano original
    return decrypted1.toString('utf-8');
  }
}
