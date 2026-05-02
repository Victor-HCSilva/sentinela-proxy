# 📖 Tutorial: Configurando o Proxy 🧑‍💻

---
### 🎯 Resumo e Objetivo 

Ao configurar nosso proxy personalizado no navegador (ex: Firefox), conseguimos interceptar e analisar todo o tráfego HTTP e HTTPS. Isso nos dá total visibilidade das requisições, auxiliando na detecção de comportamentos suspeitos ou indesejados na rede.

---
### 🛠️ Como isso é feito?    

**1. O Motor da Aplicação**
O Sentinela utiliza a biblioteca **Python `mitmproxy`** para interceptar as conexões. Por padrão, ele cria um servidor local que escuta o tráfego através do endereço `127.0.0.1:8080`.

**2. Configuração no Navegador (Firefox)**
Para que o navegador envie os dados para o Sentinela, precisamos apontar a rota:
- Vá nas configurações de Rede do navegador.
- Configure o proxy como **Manual**.
- Aponte para o IP `127.0.0.1` na porta `8080`.

![Configurações -> proxy -> manual](imgs/proxy-configuration.png)

**3. Compatibilidade e Certificados (HTTPS)**
Para que os sites seguros (HTTPS) não bloqueiem a conexão achando que é um ataque, precisamos instalar o certificado de confiança do Mitmproxy:
- Com o programa rodando, acesse a URL: `http://mitm.it/` e baixe o certificado.
- Instale e atualize as certificações do seu sistema.
- Adicione a certificação nas configurações avançadas do Firefox:
  - Pesquise por "Certificados" nas configurações, clique em "Ver Certificados" > "Importar" e adicione o certificado baixado. Marque a opção para confiar nele para identificar sites.

![Instalar certificado http://mitm.it/](imgs/install-certificate.png)
![Certificados -> adicionar certificado](imgs/add-certificate.png)

🎉 **Pronto!** Agora todo o tráfego do navegador passará antes pelo `mitmproxy` (Sentinela). 

---
### 💡 Adendo: Proxy em todo o Sistema (Ubuntu)

No **Ubuntu**, você pode colocar sua própria proxy como padrão do sistema Operacional. Dessa forma, **todos** os navegadores e aplicações usarão a proxy automaticamente. 
*(Lembre-se: ainda será necessário instalar o certificado de confiança separadamente em navegadores que usam gerenciadores de certificados próprios, como o Firefox).*

![Configuração no Ubuntu](imgs/image.png)

