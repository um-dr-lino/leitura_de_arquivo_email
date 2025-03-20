
# from imbox import Imbox
import imaplib
import json
import os
import time
import boto3
import re
from typing import Dict, Any, Optional, Tuple
import traceback
import urllib3
import email as email_parser
import base64
import xml.etree.ElementTree as ET
import unicodedata 

#CONFIGURAÇÕES DE USUARIO, EMAIL E SENHA
host = 'imap.gmail.com'
email = 'linolinocatolica@gmail.com'
password = 'yrzj nqna lota tzwp'
#FIM DA CONFIGURAÇÃO DE EMAIL E SENHA

'''CHAMA A FUNÇÃO TEXTRACT DA LAMBDA E FALA QUAL É O NOME'''
textract = boto3.client('textract', region_name='us-east-1')
http = urllib3.PoolManager()

download_folder = "/tmp" #Local para salvar o arquivo por enquanto vai ficar no meu temp
os.makedirs(download_folder, exist_ok=True)

def connect_email():
    """Conecta ao servidor IMAP e retorna a conexão."""
    print("[DEBUG] Iniciando conexão ao servidor de email")
    mail = imaplib.IMAP4_SSL(host)
    print(f"[DEBUG] Tentando login com usuário: {email}")
    mail.login(email, password)
    print("[DEBUG] Login bem-sucedido")
    return mail

def process_new_emails():
    #Busca o último e-mail não lido e processa seu anexo.
    extract_email = {}
    mail = connect_email()
    mail.select("inbox")

    # Buscar e-mails não lidos
    status, email_ids = mail.search(None, '(UNSEEN)')
    email_list = email_ids[0].split()
    
    if not email_list:
        print("Nenhum e-mail não lido encontrado.")
        return None, None  # Retorna None para indicar que não há emails

    latest_email_id = email_list[-1]  # Pega o último e-mail não lido
    #print(f"[DEBUG] Buscando conteúdo do email ID: {latest_email_id}")
    status, email_data = mail.fetch(latest_email_id, "(RFC822)")
    #print(f"[DEBUG] Status da busca de conteúdo: {status}")

    raw_email = email_data[0][1]
    print("[DEBUG] Email obtido, processando dados brutos")

    # Se raw_email for uma string, converta para bytes
    if isinstance(raw_email, str):
        print("[DEBUG] Convertendo email de string para bytes")
        raw_email = raw_email.encode('utf-8')
        msg = email_parser.message_from_bytes(raw_email) 

    msg = email_parser.message_from_bytes(raw_email) 

    print("=" * 50)
    print(f"**De:** {msg['From']}")
    print(f"**Assunto:** {msg['Subject']}")

    print("[DEBUG] Procurando por anexos no email")
    """ Criando variaveis e atribuindo valores nulo """
    document_bytes = None    
    #Função para verificar se dentro do email tem anexo
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition") is None:
            continue
        filename = part.get_filename()
        extract_email['file_name'] = filename
        if filename:
            print(f"[DEBUG] Anexo encontrado: {filename}") 
            file_path = os.path.join(download_folder, filename)
            with open(file_path, "wb") as f:
                payload = part.get_payload(decode=True)
                f.write(payload)

            # Ler os bytes do documento diretamente
            with open(file_path, "rb") as doc_file:
                document_bytes = doc_file.read()
                base64_encoded = base64.b64encode(document_bytes).decode('utf-8')
                extract_email['base64_file'] = base64_encoded
                result = get_full_text(document_bytes)
                extract_email['extracted_text'], extract_email['text_confidence'] = result
    
    if document_bytes is None:
        print("Nenhum anexo encontrado.")
    print("[DEBUG] Processamento de email concluído!")
    return extract_email

def get_full_text(document_bytes: bytes) -> Optional[Tuple[str, dict]]:
    try:
        '''Envia documento de anexo para o textract'''
        print(f"[DEBUG] Sending document to Textract")
        response = textract.detect_document_text(Document={'Bytes': document_bytes})
        print("[DEBUG] Resposta recebida do Textract")        

        '''Extrai blocos de texto da resposta da linha de cima'''
        text_blocks = [item.get('Text', '') for item in response.get('Blocks', []) if item.get('BlockType') == 'LINE']
        print(f"[DEBUG] Número de blocos de texto extraídos: {len(text_blocks)}")
        
        text_confidence = {
            item.get("Text", ""): item.get("Confidence", 0.0)
            for item in response.get("Blocks", [])
            if item.get("BlockType") in ("LINE", "WORD")
        }
        print(f"[DEBUG] Número de entradas de confiança: {len(text_confidence)}")
        print("[DEBUG] Junção de blocos de texto")
        
        '''Junta todos os blocos de texto em uma única string'''
        full_text = " ".join(text_blocks)
        print("text_full", full_text)
        
        return full_text, text_confidence
    except Exception as e:
        print(f"[ERROR] Textract error: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None, {}  # Retornando None para indicar erro

#Função que faz o match das informações, procura o RG em três padrões
def extract_rg(text: str, confidence_score: dict):
    match = re.search(r'\D(\d{1}\.\d{3}\.\d{3})\D', text)
    if not match:
        match = re.search(r'\D(\d{3}\.\d{3}\.\d{3}-\d{1})\D', text)  
        if not match:
            match = re.search(r'UF\s*(\d+)', text)
            if not match:
                match = re.search(r'GERAL\s*(\d+)', text)
    if match:
        result = match.group(1)      
        print(f"[DEBUG] RG encontrado: {result}")
        # buscar o confidence de um trecho de texto
        confidence = confidence_score.get(result, 0.0)
        print(f"[DEBUG] Confiança para o RG: {confidence}")
        return result, confidence
    print("[DEBUG] RG not found.")
    return None, 0.0  # Valor padrão para quando não encontrado

#Função que faz o match do cpf procurando o padrão 000.000.000-00
def extract_cpf(text: str, confidence_score: dict):
    match = re.search(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b', text)
    result = match.group(0) if match else None
    confidence = confidence_score.get(result, 0.0)
    print(f"[DEBUG] CPF extraction result: {result}")
    print(f"[DEBUG] CPF extraction result confidence: {confidence}")
    return result, confidence

#Função que faz o match do nome social no texto extraído
def extract_nome(text: str, confidence_score: dict):
    #Extrai o Nome Social do texto, mesmo que esteja tudo em uma única linha.
    match = re.search(r'NOME\s+([A-ZÁÀÉÈÍÌÓÒÚÙÇãõâêîôûäëïöü\s]+)\s+FILIAÇÃO', text)

    if not match:
            print("[DEBUG] 'NOME' não encontrado, tentando com 'HABILITAÇÃO'...")
            match = re.search(r'HABILITAÇÃO\s+([A-ZÁÀÉÈÍÌÓÒÚÙÇãõâêîôûäëïöü\s]+)\s+\d', text)

    if match:
            result = match.group(1).strip()
            print(f"[DEBUG] Nome encontrado: {result}")
            confidence = confidence_score.get(result, 0.0)  # Busca a confiança
            print(f"[DEBUG] Confiança para o Nome: {confidence}")
            return result, confidence

    print("[DEBUG] Nenhum nome encontrado.")
    return None, 0.0  # Retorno padrão quando não encontrado

def extract_birthdate(text: str, confidence_score: dict):
    # Expressão regular para capturar datas no formato DD/MM/AAAA, DD-MM-AAAA ou DD.MM.AAAA
    date_pattern = r'\b(\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\b'
    
    # Encontra todas as datas no texto
    matches = re.findall(date_pattern, text)

    if len(matches) >= 2:
        result = matches[1]  # Retorna a segunda data encontrada
        print(f"[DEBUG] Segunda data de nascimento encontrada: {result}")
    elif matches:
        result = matches[0]  # Se houver apenas uma data, retorna essa
        print(f"[DEBUG] Apenas uma data encontrada: {result}")
    else:
        print("[DEBUG] Nenhuma data de nascimento encontrada.")
        return None, 0.0  # Retorno padrão caso não encontre nenhuma data

    # Obtém a confiança da data extraída (se existir no dicionário)
    confidence = confidence_score.get(result, 0.0)
    print(f"[DEBUG] Confiança para a data de nascimento: {confidence}")

    return result, confidence

#importa para dentro do documento
def create_document(extract_email):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = urllib3.PoolManager()
    url = "https://isc.softexpert.com/apigateway/se/ws/dc_ws.php"
    authorization = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MzkyOTk0NTAsImV4cCI6MTg5NzA2NTg1MCwiaWRsb2dpbiI6ImFsaW5vIn0.UY5DZHix28g_pr-V8A-rJYpOCU9MPta6Lc3uKkoGxqw"
    headers = {
        "Authorization": authorization,
        "SOAPAction": "urn:document#newDocument2",
        "Content-Type": "text/xml;charset=utf-8"
    }
    cpf = clean_text(extract_email.get("cpf_number")[0])
    nome = clean_text(extract_email.get("nome_social")[0])
    rg = clean_text(extract_email.get("rg_number")[0])
    base64_rg = extract_email.get("base64_file")
    file_name = extract_email.get("file_name")
    birth_date = extract_email.get("birth_date")[0]
    iddocument = f"{cpf} - {nome}"

    if not all([cpf, nome, rg, base64_rg, file_name]):
        print("[ERRO] Dados obrigatórios ausentes!")
        return {"status_code": 400, "message": "Erro: Dados incompletos."}
    
    payload = f"""
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:document">
    <soapenv:Header/>
    <soapenv:Body>
        <urn:newDocument>
                <urn:idcategory>novocolaborador</urn:idcategory>
                <urn:iddocument>{iddocument}</urn:iddocument>
                <urn:title>{nome}</urn:title>
                <urn:dsresume>Importado via integracao</urn:dsresume>
                <urn:attributes>cpfnovo={cpf};RG={rg}</urn:attributes>
            <urn:file>
                <urn:item>
                <urn:NMFILE>{file_name}</urn:NMFILE>
                <urn:BINFILE>{base64_rg}</urn:BINFILE>
                </urn:item>
            </urn:file>
        </urn:newDocument>
    </soapenv:Body>
    </soapenv:Envelope>"""  
    http = urllib3.PoolManager()
    req = http.request('POST', url=url, headers=headers, body=payload)
    # print("[DEBUG] Resposta do servidor:", req.status, payload)
    print("Resposta: ", req.data.decode('utf-8'))
    return 
    
def clean_text(texto):
    """Remove acentos e caracteres especiais, mantendo apenas letras, números e espaços."""
    if not isinstance(texto, str):  
        return texto  # Retorna como está se não for string

    # Remove acentos
    texto_sem_acentos = ''.join(
        c for c in unicodedata.normalize('NFD', texto) 
        if unicodedata.category(c) != 'Mn'
    )
    # Remove caracteres especiais (mantém apenas letras, números e espaços)
    texto_limpo = re.sub(r'[^A-Za-z0-9\s]', '', texto_sem_acentos)
    
    return texto_limpo
    
def lambda_handler(event, context):
    try:
        # Processar um único email e obter o texto extraído
        extract_email = process_new_emails()

        # Verificar se o email foi extraído corretamente
        if not extract_email or 'extracted_text' not in extract_email or not extract_email['extracted_text']:
            print("[DEBUG] Nenhum email encontrado ou sem texto extraído. Processando corpo da solicitação...")
            return {
                'statusCode': 404, 
                'body': json.dumps({
                    'message': 'No content to process'
                })
            }

        # Processar o texto extraído diretamente
        extract_email['cpf_number'] = extract_cpf(extract_email['extracted_text'], extract_email['text_confidence'])
        extract_email['rg_number'] = extract_rg(extract_email['extracted_text'], extract_email['text_confidence'])
        extract_email['nome_social'] = extract_nome(extract_email['extracted_text'], extract_email['text_confidence'])
        extract_email['birth_date'] = extract_birthdate(extract_email['extracted_text'], extract_email['text_confidence'])
        create_document(extract_email)
        return {
            'statusCode': 200, 
            'body': json.dumps({
                'message': 'Email processed successfully'
            })
        }

    except Exception as e:
        print(f"[ERROR] Erro no processamento: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500, 
            'body': json.dumps({
                'error': str(e)
            })
        }