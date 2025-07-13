import base64
import json
import os
import zipfile
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.ssl.v20191205 import models, ssl_client

os.chdir(os.path.dirname(os.path.abspath(__file__)))

TMP_ZIP_FILE = "tmp_cert_downloader.zip"

CONF = json.loads(open("config.json", "r", encoding="utf-8").read())


# 错误输出函数，可自行对接相应API进行通知
def logError(msg):
    print(msg)


def getClient():
    try:
        cred = credential.Credential(CONF["SecretId"], CONF["SecretKey"])
        client = ssl_client.SslClient(cred, "ap-guangzhou")
        return client
    except TencentCloudSDKException as err:
        logError("CertDownloader getClient failed, error: {}".format(err))
        raise err


def getCerts(client):
    try:
        req = models.DescribeCertificatesRequest()
        req.Limit = 1000
        req.CertificateType = "SVR"
        req.CertificateStatus = [1]
        resp = client.DescribeCertificates(req)
        return resp
    except TencentCloudSDKException as err:
        logError("CertDownloader getCertList failed, error: {}".format(err))
        raise err


def parseNeededCerts(certs):
    toDownloadCerts = []
    for neededCert in CONF["NeededCerts"]:
        success = False
        for cert in certs:
            certDomains = set(cert.SubjectAltName)
            neededDomains = set(neededCert["Domains"])
            if certDomains & neededDomains != neededDomains:
                continue
            toDownloadCerts.append(
                {
                    "CertId": cert.CertificateId,
                    "Domains": neededCert["Domains"],
                    "CertSavePath": neededCert["CertSavePath"],
                    "KeySavePath": neededCert["KeySavePath"],
                }
            )
            print(
                "Found CertId {} for domains: {}".format(
                    cert.CertificateId, neededDomains
                )
            )
            success = True
            break
        if not success:
            logError(
                "CertDownloader no available certificate for domains: {}".format(
                    neededCert["Domains"]
                )
            )
    return toDownloadCerts


def downloadAndSaveCerts(client, certs):
    for cert in certs:
        try:
            req = models.DownloadCertificateRequest()
            req.CertificateId = cert["CertId"]
            resp = client.DownloadCertificate(req)
            if resp.ContentType != "application/zip":
                raise Exception(
                    "DownloadCertificate failed, ContentType is {}".format(
                        resp.ContentType
                    )
                )
            if resp.Content is None or len(resp.Content) == 0:
                raise Exception("DownloadCertificate failed, Content is None or empty")
            zipBinary = base64.b64decode(resp.Content)
            if os.path.exists(TMP_ZIP_FILE):
                os.remove(TMP_ZIP_FILE)
            with open(TMP_ZIP_FILE, "wb") as f:
                f.write(zipBinary)
            z = zipfile.ZipFile(TMP_ZIP_FILE, "r")
            for filepath in z.namelist():
                if filepath.startswith("Nginx/"):
                    if filepath.endswith(".crt"):
                        certBinary = z.read(filepath)
                        if len(certBinary) == 0:
                            raise Exception(
                                "Certificate cert file is empty: {}".format(
                                    cert["CertId"]
                                )
                            )
                        with open(cert["CertSavePath"], "wb") as f:
                            f.write(certBinary)
                    elif filepath.endswith(".key"):
                        keyBinary = z.read(filepath)
                        if len(keyBinary) == 0:
                            raise Exception(
                                "Certificate key file is empty: {}".format(
                                    cert["CertId"]
                                )
                            )
                        with open(cert["KeySavePath"], "wb") as f:
                            f.write(keyBinary)
            z.close()
            os.remove(TMP_ZIP_FILE)
            print(
                "CertDownloader downloadAndSaveCerts success for domains: {}".format(
                    cert["Domains"]
                )
            )
        except (Exception, TencentCloudSDKException) as err:
            logError(
                "CertDownloader downloadAndSaveCerts failed for domains: {}\nError: {}".format(
                    cert["Domains"], err
                )
            )


if __name__ == "__main__":
    client = getClient()
    certs = getCerts(client)
    if certs is None or len(certs.Certificates) == 0:
        print("No certificates found")
    else:
        print("Found {} available certificates".format(len(certs.Certificates)))
        neededDownloadCers = parseNeededCerts(certs.Certificates)
        downloadAndSaveCerts(client, neededDownloadCers)
