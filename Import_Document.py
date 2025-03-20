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