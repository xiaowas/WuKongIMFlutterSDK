library encryptor;

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class Encryptor {
  /// encrypt the plainText with user key and random iv and return encryted text
  static String encrypt(
    String key,
    String plainText,
  ) {
    final ei = _encrypterInitilization(
      key: key,
    );
    final encrypter = ei.encrypter;
    final iv = ei.iv;
    return encrypter.encrypt(plainText, iv: iv).base64;
  }

  /// decrypt the plainText with user key and random iv and return plain Text
  /// if will encryption [randomIV] is passed than make sure to pass the same randomIV to decrypt.
  static String decrypt(
    String key,
    String encrpytedPharse,
  ) {
    final ei = _encrypterInitilization(
      key: key,
    );
    final encrypter = ei.encrypter;
    final iv = ei.iv;
    return encrypter.decrypt64(encrpytedPharse, iv: iv);
  }

  // Encrypter intializer
  static EncrypterIntializer _encrypterInitilization({
    required String key,
    String? randomIV,
  }) {
    // hashing key
    var bytes = utf8.encode(key);
    var digest = sha256.convert(bytes);
    var fDigest = md5.convert(digest.bytes);
    final hashKey = Key.fromUtf8(fDigest.toString());

    // intiail vector
    final iv = randomIV != null ? IV.fromUtf8(randomIV) : IV.fromLength(16);

    // encryption
    final encrypter = Encrypter(
      AES(
        hashKey,
        mode: AESMode.cfb64,
      ),
    );
    return EncrypterIntializer(encrypter: encrypter, iv: iv);
  }
}

// Custom type for Encryptor intializer
class EncrypterIntializer {
  final Encrypter encrypter;
  final IV iv;

  EncrypterIntializer({required this.encrypter, required this.iv});
}
