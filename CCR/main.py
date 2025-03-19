
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

'''CONFIGURAÇÕES DE USUARIO, EMAIL E SENHA'''
host = 'imap.gmail.com'
email = 'linolinocatolica@gmail.com'
password = 'yrzj nqna lota tzwp'

'''FIM DA CONFIGURAÇÃO DE EMAIL E SENHA
   É NECESSÁRIO FAZER A PARTE DE SEGURANÇA, CRIAR UMA VARIAVEL DO SISTEMA PARA NÃO MOSTRAR AS SENHAS
'''
'''CHAMA A FUNÇÃO TEXTRACT DA LAMBDA E FALA QUAL É O NOME'''
textract = boto3.client('textract', region_name='us-east-1')
http = urllib3.PoolManager()

download_folder = "/tmp" #Local para salvar o arquivo por enquanto vai ficar no meu temp
os.makedirs(download_folder, exist_ok=True)

# Adicionar DEBUG para importação de email
# print("[DEBUG] Importando módulos necessários")
def connect_email():
    """Conecta ao servidor IMAP e retorna a conexão."""
    print("[DEBUG] Iniciando conexão ao servidor de email")
    mail = imaplib.IMAP4_SSL(host)
    print(f"[DEBUG] Tentando login com usuário: {email}")
    mail.login(email, password)
    print("[DEBUG] Login bem-sucedido")
    return mail


# entra no email e verifica o último email recebido
# verifica se tem emails nao lido
def process_new_emails():
    """Busca o último e-mail não lido e processa seu anexo."""
    #print("[DEBUG] Iniciando processamento de novos emails")
    extract_email = {}
    mail = connect_email()
    #print("[DEBUG] Selecionando caixa de entrada")
    mail.select("inbox")

    # Buscar e-mails não lidos
    #print("[DEBUG] Buscando emails não lidos")
    status, email_ids = mail.search(None, '(UNSEEN)')
    #print(f"[DEBUG] Status da busca: {status}")
    email_list = email_ids[0].split()
    #print(f"[DEBUG] Quantidade de emails não lidos: {len(email_list)}")

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
    extracted_text = None
    text_confidence = None
    
    '''Função para verificar se dentro do email tem anexo
    msg.walk() percorre o email para verificar se tem anexo
    '''
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ''' O cabeçalho  do anexo começa com "Content-Disposition: attachment"
        Se não tiver, ele pula para o próximo anexo]
        O cabeçalho "Content-Disposition" geralmente indica se o conteúdo é um anexo (e.g., "attachment; filename=documento.pdf")'''

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
                print(f"[DEBUG] Base65 do arquivo: {base64_encoded[:20]}")
                result = get_full_text(document_bytes)
                extract_email['extracted_text'], extract_email['text_confidence'] = result
    
    if document_bytes is None:
        print("Nenhum anexo encontrado.")
    print("[DEBUG] Processamento de email concluído!")
    return extract_email, {}

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
        #print("text_full", full_text)
        
        return full_text, text_confidence
    except Exception as e:
        print(f"[ERROR] Textract error: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None, {}  # Retornando None para indicar erro

def extract_text_from_document(document_bytes):
    '''Essa função recebe um documento como bytes, chama o Amazon Textract para analisar os formulários contidos nele e retorna a resposta da análise.'''
    print("[DEBUG] Chamando extract_text_from_document")
    client = boto3.client('textract', region_name=os.getenv('AWS_REGION', 'us-east-1'))
    response = client.analyze_document(
        Document={'Bytes': document_bytes},
        FeatureTypes=['FORMS']
    )
    print("[DEBUG] Análise de documento concluída")
    return response

def identify_document_type(text_data, provided_type):
    print("[DEBUG] Identificando tipo de documento")
    if "Registro Geral" in text_data or "RG" in text_data:
        print("[DEBUG] Documento identificado como RG")
        return "RG"
    print("[DEBUG] Tipo de documento não identificado")
    return None

# Nova função para processar diretamente o texto extraído
def process_extracted_text(extracted_text, text_confidence):
    extracted_info = {}
    
    if extracted_text:
        try:
            # Identificar o tipo de documento (opcional)
            document_type = identify_document_type(extracted_text, None)
            
            # Extrair RG diretamente do texto
            print("[DEBUG] Chamando extract_rg")
            rg_result = extract_rg(extracted_text, text_confidence)
            cpf_result = extract_cpf(extracted_text, text_confidence)
            nome_social = extract_social_name(extracted_text, text_confidence)
            print(f"[DEBUG] Resultado extract_rg: {rg_result}")
            print(f"[DEBUG] Resultado cnh_result: {cpf_result}")
            print(f"[DEBUG] Resultado para o nome socal: {nome_social}")
            if isinstance(rg_result, tuple) and len(rg_result) == 2:
                extracted_info['rg_number'], extracted_info['confidence_score_rg'] = rg_result
                print(f"[DEBUG] RG extraction result: {extracted_info['rg_number']}, confidence: {extracted_info['confidence_score_rg']}")
            if isinstance(cpf_result, tuple):
                extracted_info['cpf_number'], extracted_info['confidence_score_cpf'] = cpf_result
                print(f"[DEBUG] CPF extraction result: {extracted_info['cpf_number']}, confidence: {extracted_info['confidence_score_cpf']}")
            if isinstance(nome_social, tuple):
                extracted_info['nome_social'], extracted_info['confidence_score_name'] = nome_social
                print(f"[DEBUG] nome_social result: {extracted_info['nome_social']}, confidence: {extracted_info['nome_social']}")
        except Exception as e:
            print(f"[ERROR] Exception processing extracted text: {str(e)}")
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
    print(f"[DEBUG] Informações extraídas: {extracted_info}")
    return extracted_info

def import_document(extracted_info):
    
    url = "https://isc.softexpert.com/apigateway/se/ws/dc_ws.php"
    authorization = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MzkyOTk0NTAsImV4cCI6MTg5NzA2NTg1MCwiaWRsb2dpbiI6ImFsaW5vIn0.UY5DZHix28g_pr-V8A-rJYpOCU9MPta6Lc3uKkoGxqw"
    headers = {
        "Authorization": authorization,
        "SOAPAction": "urn:document#newDocument2",
        "Content-Type": "text/xml;charset=utf-8"
    }
    cpf = extracted_info.get("cpf_number")
    nome = extracted_info.get("nome_social")
    rg = extracted_info.get("rg_number")
    base64_rg = extracted_info.get('base64_file')
    file_name = extracted_info.get('file_name')
    iddocument = f"{cpf} - {nome}"
    print("[DEBUG] Este é o CPF",cpf)
    print("[DEBUG] Este é o nome",nome)
    print("[DEBUG] Este é o title", iddocument)
    
    payload = f"""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:document">
        <soapenv:Header/>
        <soapenv:Body>
            <urn:newDocument2>
                <!--You may enter the following 13 items in any order-->
                <urn:CategoryID>novocolaborador</urn:CategoryID>
                <urn:DocumentID>iddocument</urn:DocumentID>
                <urn:Title>nome</urn:Title>
                <urn:Attributes>
                    <urn:item>
                    <urn:ID>tgncnpj</urn:ID>
                        <urn:item>
                            <urn:Value>{cpf}</urn:Value>
                        </urn:item>
                    <urn:ID>RG</urn:ID>
                        <urn:item>
                            <urn:Value>{rg}</urn:Value>
                        </urn:item>
                    </urn:item>
                </urn:Attributes>
                <urn:Files>
                    <urn:item>
                    <urn:Name>{file_name}</urn:Name>
                    <urn:Content>{base64_rg}</urn:Content>
                    </urn:item>
                </urn:Files>
            </urn:newDocument2>
        </soapenv:Body>
        </soapenv:Envelope>"""
        
    http = urllib3.PoolManager()
    req = http.request('POST', url=url, headers=headers, body=payload.encode('utf-8'))  # Envia em UTF-8
    print(f"Req")
    return {"status_code": req.status}

'''Função que faz o match das informações, procura o RG em dois padrões'''
def extract_rg(text: str, confidence_score: dict):
    match = re.search(r'\D(\d{1}\.\d{3}\.\d{3})\D', text)
    if not match:
        match = re.search(r'\D(\d{3}\.\d{3}\.\d{3}-\d{1})\D', text)  
        if not match:
            match = re.search(r'UF\s*(\d+)', text)
    if match:
        result = match.group(1)      
        print(f"[DEBUG] RG encontrado: {result}")
        # buscar o confidence de um trecho de texto
        confidence = confidence_score.get(result, 0.0)
        print(f"[DEBUG] Confiança para o RG: {confidence}")
        return result, confidence
    print("[DEBUG] RG not found.")
    return None, 0.0  # Valor padrão para quando não encontrado

def extract_cpf(text: str, confidence_score: dict):
    match = re.search(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b', text)
    result = match.group(0) if match else None
    confidence = confidence_score.get(result, 0.0)
    print(f"[DEBUG] CPF extraction result: {result}")
    print(f"[DEBUG] CPF extraction result confidence: {confidence}")
    return result, confidence

'''Função que faz o match do nome social no texto extraído'''
def extract_social_name(text: str, confidence_score: dict):
    """
    Extrai o Nome Social do texto, mesmo que esteja tudo em uma única linha.
    """
    match = re.search(r'HABILITAÇÃO\s+([A-Z\s]+?)\s+\d', text)  
    if match:
        result = match.group(1).strip()
        print(f"[DEBUG] Nome social encontrado: {result}")
        confidence = confidence_score.get(result, 0.0)  # Busca a confiança
        print(f"[DEBUG] Confiança para o Nome Social: {confidence}")
        return result, confidence

    print("[DEBUG] Nome Social não encontrado.")
    return None, 0.0  # Retorno padrão quando não encontrado

def lambda_handler(event, context):
    try:
        # Processar um único email e obter o texto extraído
        # extracted_text, text_confidence = process_new_emails()
        extract_email = process_new_emails()
        if extract_email['extracted_text']:
            # Processar o texto extraído diretamente
            extracted_info = process_extracted_text(extract_email['extracted_text'], extract_email['text_confidence'])
            extract_email['cpf_number'] = extracted_info['cpf_number']
            extract_email['rg_number'] = extracted_info['rg_number']
            extract_email['nome_social'] = extracted_info['nome_social']
            import_document(extract_email)
            return {
                'statusCode': 200, 
                'body': json.dumps({
                    'message': 'Email processed successfully', 
                    'data': extracted_info
                })
            }
        
        # Se não encontrou email, tenta processar a solicitação do corpo
        print("[DEBUG] Nenhum email encontrado ou sem texto extraído. Processando corpo da solicitação...")
    except Exception as e:
        print(f"[ERROR] Erro no processamento: {str(e)}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500, 
            'body': json.dumps({
                'error': str(e)
            })
        }
    
    # Caso padrão
    return {
        'statusCode': 404, 
        'body': json.dumps({
            'message': 'No content to process'
        })
    }