Utility lib in dart for building and validating CMS/PKCS7 detached signatures.

Usage example:
```dart
// Test data
String base64data = 'cBQCV9BfdogmhIffB4HpFyTNA8q1fsxTBJIwt1P39cU=';
String certificatePath = 'test/resource/certificate.pem';
String privateKeyPath = 'test/resource/private_key_pkcs8.pem';

// Create an instance of PKCS7Builder
var pkcs7Builder = PKCS7Builder(data, certificatePath, privateKeyPath);

// Call the create method
Uint8List pkcs7Signature = pkcs7Builder.create();

// Validate the result
expect(pkcs7Signature, isNotNull);
expect(pkcs7Signature.isNotEmpty, isTrue);

// Print the PKCS7 signature as a Base64 string
String base64Signature = base64Encode(pkcs7Signature);
print('Generated PKCS7 Signature (Base64): $base64Signature');
```
