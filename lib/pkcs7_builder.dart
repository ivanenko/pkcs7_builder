import 'dart:convert';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';
import 'package:basic_utils/basic_utils.dart';
import 'dart:io';

class PKCS7Builder {
	late RSAPrivateKey privateKey;
    late Uint8List certificateDer;
    late Uint8List data;

	PKCS7Builder(String base64Hash, String certificatePath, String privateKeyPath) {
	  data = base64Decode(base64Hash);
      privateKey = _loadRSAPrivateKey(privateKeyPath);
      certificateDer = _loadCertificate(certificatePath);
	}

	/// Основной метод создания PKCS7 подписи.
	Uint8List create() {
	  ASN1Set signedAttributes = prepareSignedAttributes();
	  Uint8List signature = signAttributes(signedAttributes);
	  return createPKCS7(signedAttributes, signature);
	}
	
	/// Подготавливает Signed Attributes Set.
	ASN1Set prepareSignedAttributes() {
	  final signedAttributes = ASN1Set();

	  // MessageDigest Attribute
	  signedAttributes.add(
	    ASN1Sequence()
	      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.4')) // OID for messageDigest
	      ..add(ASN1Set()..add(ASN1OctetString(data)))
	  );

	  // ContentType Attribute
	  signedAttributes.add(
	    ASN1Sequence()
	      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.3')) // OID for contentType
	      ..add(ASN1Set()..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.1'))) // OID for data
	  );

	  // SigningTime Attribute
	  DateTime now = DateTime.now().toUtc();
	  signedAttributes.add(
	    ASN1Sequence()
	      ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.5')) // OID for signingTime
	      ..add(ASN1Set()..add(ASN1UtcTime(now)))
	  );

	  // CMSAlgorithmProtection Attribute	  
	  signedAttributes.add(
	  	ASN1Sequence()
	  	  ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.52')) // OID for cmsAlgorithmProtect
	  	  ..add(
	  	  	ASN1Set()
	  	  	  ..add(
	  	  	  	ASN1Sequence() // protectionSequence
	  	  	  	  ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.1')) // SHA-256
	  			  ..add(ASN1Integer(BigInt.from(1))) // Version
	              ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.11')) // SHA256WithRSA
	  	  	  )
	  	  )
	  );

	  // SigningCertificateV2 Attribute
	  Uint8List certHash = SHA256Digest().process(certificateDer);	  
	  signedAttributes.add(
	  	ASN1Sequence()
	  	  ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.9.16.2.47')) // OID for signingCertificateV2
	  	  ..add(
	  	  	ASN1Set()
	  	  	  ..add(
	  	  	  	ASN1Sequence() // attrValue
	  	  	  	  ..add(
	  	  	  	  	ASN1Sequence() // certs
	  	  	  	  	  ..add(
	  	  	  	  	  	ASN1Sequence() // essCertIDv2
	  	  	  	  	  	  ..add(ASN1OctetString(certHash))
	  	  	  	  	  	  ..add(_getIssuerAndSerialNumber(certificateDer))
	  	  	  	  	  )
	  	  	  	  )
	  	  	  )
	  	  )
	  );

	  return signedAttributes;
	}

	/// Подписывает Signed Attributes приватным RSA ключом.
	Uint8List signAttributes(ASN1Set signedAttributes) {
	  final signer = RSASigner(SHA256Digest(), '0609608648016503040201'); // SHA-256 OID
	  signer.init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
	  return signer.generateSignature(signedAttributes.encodedBytes).bytes;
	}

	Uint8List createPKCS7(ASN1Set signedAttributes, Uint8List signature) {
	  // ContentInfo
	  final contentInfo = ASN1Sequence()
	    ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.2')); // OID for signedData

	  final signedData = ASN1Sequence()
	    ..add(ASN1Integer(BigInt.from(1))) // Version
	    ..add(
	      ASN1Set() // Digest Algorithms
	        ..add(
	          ASN1Sequence()
	            ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.1')) // SHA-256 OID
	        ),
	    ) 
	    ..add(
	      ASN1Sequence()
	        ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.7.1')), // Encapsulated ContentInfo OID for data
	    );

	  // Certificates
	  final parser = ASN1Parser(certificateDer);
	  final certSequence = parser.nextObject() as ASN1Sequence;
	  
	  // Добавление сертификата в тегированный объект [0] EXPLICIT
	  signedData.add(ASN1Parser(_createExplicitTaggedObject(0, certSequence.encodedBytes)).nextObject());

	  // SignerInfo
	  final signerInfo = ASN1Sequence()
	    ..add(ASN1Integer(BigInt.from(1))) // SignerInfo Version
	    ..add(_getIssuerAndSerialNumber(certificateDer))
	    ..add(
	      ASN1Sequence()
	        ..add(ASN1ObjectIdentifier.fromComponentString('2.16.840.1.101.3.4.2.1')), // DigestAlgorithm (SHA-256 OID)
	    )
	    ..add(ASN1Parser(_createImplicitTaggedObject(0, signedAttributes.encodedBytes)).nextObject()) // SignedAttributes (IMPLICIT [0])
	    ..add(
	      ASN1Sequence()
	        ..add(ASN1ObjectIdentifier.fromComponentString('1.2.840.113549.1.1.11')) // SignatureAlgorithm (sha256WithRSAEncryption OID)
	        ..add(ASN1Null()),
	    )
	    ..add(ASN1OctetString(signature)); // SignatureValue

	  // Добавление SignerInfo в SET
	  signedData.add(
	    ASN1Set()..add(signerInfo)
	  );

	  // Добавление signedData в тегированный объект [0] EXPLICIT
	  contentInfo.add(ASN1Parser(_createExplicitTaggedObject(0, signedData.encodedBytes)).nextObject());

	  return contentInfo.encodedBytes;
	}

	ASN1Sequence _getIssuerAndSerialNumber(Uint8List certificateDer) {	  
	  final parser = ASN1Parser(certificateDer);
	  final certSequence = parser.nextObject() as ASN1Sequence;
	  var tbsCertSequence = certSequence.elements[0] as ASN1Sequence;
	  var serialNumber = tbsCertSequence.elements[1] as ASN1Integer;
	  var issuerSequence = tbsCertSequence.elements[3] as ASN1Sequence;

	  final issuerAndSerialNumber = ASN1Sequence();
	  issuerAndSerialNumber.add(issuerSequence);
	  issuerAndSerialNumber.add(serialNumber);

	  return issuerAndSerialNumber;
	}

	/// Создает ASN.1 тегированный объект.
	Uint8List _createExplicitTaggedObject(int tagNumber, Uint8List encodedValue) {
	  final bytes = BytesBuilder();
	  final tag = 0xA0 | (tagNumber & 0x1F);
	  bytes.addByte(tag);
	  final length = encodedValue.length;
	  if (length < 128) {
	    bytes.addByte(length);
	  } else {
	    final lengthBytes = <int>[];
	    int remaining = length;
	    while (remaining > 0) {
	      lengthBytes.insert(0, remaining & 0xFF);
	      remaining >>= 8;
	    }
	    bytes.addByte(0x80 | lengthBytes.length);
	    bytes.add(lengthBytes);
	  }
	  bytes.add(encodedValue);
	  return bytes.toBytes();
	}

	Uint8List _createImplicitTaggedObject(int tagNumber, Uint8List encodedValue) {
	  // Заменяем первый байт на IMPLICIT тег (0x80 для контекстно-зависимого тега + номер тега)
	  // Почему то с байтом 0x80 не работает. Нужно применять байт 0xA0
	  // encodedValue[0] = 0x80 | (tagNumber & 0x1F);
	  encodedValue[0] = 0xA0 | (tagNumber & 0x1F);
	  return encodedValue;
	}

	/// Загружает RSA приватный ключ из PEM файла.
	RSAPrivateKey _loadRSAPrivateKey(String path) {
	  final pem = File(path).readAsStringSync();
	  return CryptoUtils.rsaPrivateKeyFromPem(pem);
	}

	/// Загружает сертификат из PEM файла как набор байт в DER.
	Uint8List _loadCertificate(String path) {
	  String certPem = File(path).readAsStringSync();
	  Uint8List certificateDer = CryptoUtils.getBytesFromPEMString(certPem);
	  return certificateDer;
	}

	/// Загружает сертификат из PEM файла и возвращает X509CertificateData.
	X509CertificateData _loadCertificateX509(String path) {
	  final pem = File(path).readAsStringSync();
	  return X509Utils.x509CertificateFromPem(pem);
	}
}