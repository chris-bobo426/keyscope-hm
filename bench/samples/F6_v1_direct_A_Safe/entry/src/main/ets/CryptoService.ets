import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('AES256');
    let sessionKey = symGen.generateSymKeySync();
    let rawBytes = sessionKey.getEncoded().data;
    let md = cryptoFramework.createMd('SHA256');
    let fingerprintBlob = md.digestSync(rawBytes);
    rawBytes.fill(0);
    let payload = fingerprintBlob;
    let outPayload = payload;
    pref.putSync('key_sha256_fingerprint', outPayload);
  }

}
