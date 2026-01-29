import { DyCrypt, packData, unpackData } from '../src/index.js';
import { writeFileSync, readFileSync } from 'node:fs';

/**
 * Demonstração completa do DyCrypt
 * 
 * Este exemplo mostra:
 * 1. Como criptografar dados em cascata
 * 2. Como salvar em formato binário .secreto
 * 3. Como carregar e descriptografar
 */

async function demo() {
  console.log('🔐 DyCrypt - Demo de Criptografia em Cascata\n');
  console.log('='.repeat(60));

  // ========================================
  // 1. Inicialização
  // ========================================
  const masterPassword = 'SuperSecret2026!@#';
  const dycrypt = new DyCrypt(masterPassword);
  
  const dadosSensiveis = `
    Dados confidenciais da empresa XYZ
    -------------------------------------
    Cartão de Crédito: 4532-1234-5678-9010
    CVV: 123
    Validade: 12/2028
    Titular: João Silva
  `.trim();

  console.log('\n📝 Dados originais (texto plano):');
  console.log(dadosSensiveis);

  // ========================================
  // 2. Criptografia em Cascata
  // ========================================
  console.log('\n🔒 Iniciando criptografia em cascata...');
  console.log('   ➜ Camada 1: AES-256-GCM');
  console.log('   ➜ Camada 2: ChaCha20-Poly1305');
  
  const encrypted = await dycrypt.encrypt(dadosSensiveis);
  
  console.log('\n✅ Criptografia concluída!');
  console.log('\nMetadados gerados:');
  console.log(`   Salt 1: ${encrypted.salt1.substring(0, 16)}...`);
  console.log(`   Salt 2: ${encrypted.salt2.substring(0, 16)}...`);
  console.log(`   IV 1: ${encrypted.iv1.substring(0, 16)}...`);
  console.log(`   IV 2: ${encrypted.iv2.substring(0, 16)}...`);
  console.log(`   Auth Tag 1: ${encrypted.authTag1.substring(0, 16)}...`);
  console.log(`   Auth Tag 2: ${encrypted.authTag2.substring(0, 16)}...`);
  console.log(`   Ciphertext: ${encrypted.ciphertext.substring(0, 32)}...`);

  // ========================================
  // 3. Salvar em formato binário .secreto
  // ========================================
  console.log('\n💾 Salvando em formato binário customizado (.secreto)...');
  
  // Converter base64 para Buffers
  const salt1 = Buffer.from(encrypted.salt1, 'base64');
  const salt2 = Buffer.from(encrypted.salt2, 'base64');
  const iv1 = Buffer.from(encrypted.iv1, 'base64');
  const iv2 = Buffer.from(encrypted.iv2, 'base64');
  const authTag1 = Buffer.from(encrypted.authTag1, 'base64');
  const authTag2 = Buffer.from(encrypted.authTag2, 'base64');
  const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
  
  // Empacotar TUDO em um único arquivo (sem precisar de .meta)
  const packed = packData(salt1, salt2, iv1, iv2, authTag1, authTag2, ciphertext);
  
  // Salvar em arquivo
  const filename = 'dados-criptografados.dy';
  writeFileSync(filename, packed);
  
  console.log(`✅ Arquivo salvo: ${filename}`);
  console.log(`   Tamanho: ${packed.length} bytes`);
  console.log(`   Estrutura:`);
  console.log(`   - Header: 88 bytes (2 salts + 2 ivs + 2 auth tags)`);
  console.log(`   - Payload: ${packed.length - 88} bytes`);

  // ========================================
  // 4. Carregar e descriptografar
  // ========================================
  console.log('\n🔓 Carregando e descriptografando...');
  
  // Ler arquivo binário
  const loadedBuffer = readFileSync(filename);
  
  // Desempacotar componentes (agora tudo vem do arquivo!)
  const unpacked = unpackData(loadedBuffer);
  console.log('✅ Componentes extraídos com sucesso');
  
  // Reconstruir objeto EncryptedData
  const reconstructed = {
    salt1: unpacked.salt1.toString('base64'),
    salt2: unpacked.salt2.toString('base64'),
    iv1: unpacked.iv1.toString('base64'),
    iv2: unpacked.iv2.toString('base64'),
    authTag1: unpacked.authTag1.toString('base64'),
    authTag2: unpacked.authTag2.toString('base64'),
    ciphertext: unpacked.encryptedData.toString('base64'),
  };
  
  // Descriptografar
  const decrypted = await dycrypt.decrypt(reconstructed);
  
  console.log('\n✅ Descriptografia concluída!');
  console.log('\n📝 Dados recuperados:');
  console.log(decrypted);

  // ========================================
  // 5. Verificação
  // ========================================
  console.log('\n🔍 Verificação de integridade:');
  if (decrypted === dadosSensiveis) {
    console.log('✅ SUCESSO: Dados recuperados são idênticos aos originais');
  } else {
    console.log('❌ ERRO: Dados corrompidos ou senha incorreta');
  }

  console.log('\n' + '='.repeat(60));
  console.log('🎉 Demo concluída com sucesso!');
}

// Executar demo
demo().catch((err) => {
  console.error('❌ Erro:', err.message);
  process.exit(1);
});
