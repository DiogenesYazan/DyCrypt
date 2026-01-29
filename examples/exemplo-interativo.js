import { DyCrypt, packData, unpackData } from '../dist/index.js';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import * as readline from 'node:readline';

// cria interface pra ler input do usuario
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// funcao helper pra fazer pergunta
function perguntar(texto) {
  return new Promise((resolve) => {
    rl.question(texto, (resposta) => {
      resolve(resposta);
    });
  });
}

async function main() {
  console.clear();
  console.log('='.repeat(50));
  console.log('   DyCrypt - Criptografia Cascata');
  console.log('   Por Diogenes Yuri');
  console.log('='.repeat(50));
  console.log();

  // pergunta o que o user quer fazer
  console.log('O que você quer fazer?');
  console.log('1 - Criptografar um texto');
  console.log('2 - Descriptografar um arquivo .dy');
  console.log();

  const opcao = await perguntar('Digite 1 ou 2: ');

  if (opcao === '1') {
    // CRIPTOGRAFAR
    console.log();
    const senha = await perguntar('Digite sua senha mestra: ');
    
    console.log();
    console.log('Digite o texto secreto (Enter duas vezes para finalizar):');
    let texto = '';
    let linha = await perguntar('');
    while (linha !== '') {
      texto += linha + '\n';
      linha = await perguntar('');
    }

    if (!texto.trim()) {
      console.log('Você não digitou nada!');
      rl.close();
      return;
    }

    console.log();
    console.log('Criptografando...');
    
    // cria o objeto de criptografia
    const dycrypt = new DyCrypt(senha);
    
    // criptografa
    const resultado = await dycrypt.encrypt(texto.trim());
    
    console.log('✓ Primeira camada (AES-256) aplicada');
    console.log('✓ Segunda camada (ChaCha20) aplicada');
    
    // empacota tudo num buffer
    const salt1 = Buffer.from(resultado.salt1, 'base64');
    const salt2 = Buffer.from(resultado.salt2, 'base64');
    const iv1 = Buffer.from(resultado.iv1, 'base64');
    const iv2 = Buffer.from(resultado.iv2, 'base64');
    const authTag1 = Buffer.from(resultado.authTag1, 'base64');
    const authTag2 = Buffer.from(resultado.authTag2, 'base64');
    const cifrado = Buffer.from(resultado.ciphertext, 'base64');
    
    const arquivoFinal = packData(salt1, salt2, iv1, iv2, authTag1, authTag2, cifrado);
    
    // salva no arquivo
    const nomeArquivo = await perguntar('\nNome do arquivo (sem extensão): ');
    const caminhoCompleto = nomeArquivo + '.dy';
    
    writeFileSync(caminhoCompleto, arquivoFinal);
    
    console.log();
    console.log('✓ Arquivo salvo:', caminhoCompleto);
    console.log('✓ Tamanho:', arquivoFinal.length, 'bytes');
    console.log();
    console.log('IMPORTANTE: Guarde bem esse arquivo E a senha!');

  } else if (opcao === '2') {
    // DESCRIPTOGRAFAR
    console.log();
    const nomeArquivo = await perguntar('Nome do arquivo .dy (com extensão): ');
    
    if (!existsSync(nomeArquivo)) {
      console.log('Arquivo não encontrado!');
      rl.close();
      return;
    }
    
    const senha = await perguntar('Digite a senha mestra: ');
    
    console.log();
    console.log('Descriptografando...');
    
    try {
      // le o arquivo
      const bufferArquivo = readFileSync(nomeArquivo);
      
      // desempacota (agora pega tudo do arquivo!)
      const desempacotado = unpackData(bufferArquivo);
      
      // monta o objeto completo
      const dadosCriptografados = {
        salt1: desempacotado.salt1.toString('base64'),
        salt2: desempacotado.salt2.toString('base64'),
        iv1: desempacotado.iv1.toString('base64'),
        iv2: desempacotado.iv2.toString('base64'),
        authTag1: desempacotado.authTag1.toString('base64'),
        authTag2: desempacotado.authTag2.toString('base64'),
        ciphertext: desempacotado.encryptedData.toString('base64')
      };
      
      // descriptografa
      const dycrypt = new DyCrypt(senha);
      const textoOriginal = await dycrypt.decrypt(dadosCriptografados);
      
      console.log('✓ Segunda camada removida');
      console.log('✓ Primeira camada removida');
      console.log();
      console.log('='.repeat(50));
      console.log('TEXTO DESCRIPTOGRAFADO:');
      console.log('='.repeat(50));
      console.log(textoOriginal);
      console.log('='.repeat(50));
      
    } catch (erro) {
      console.log();
      console.log('✗ Erro ao descriptografar!');
      console.log('  Motivo:', erro.message);
      console.log();
      console.log('Possíveis causas:');
      console.log('  - Senha incorreta');
      console.log('  - Arquivo corrompido');
      console.log('  - Arquivo foi modificado');
    }

  } else {
    console.log('Opção inválida!');
  }

  rl.close();
}

// executa
main().catch((erro) => {
  console.log('Deu ruim:', erro.message);
  process.exit(1);
});
