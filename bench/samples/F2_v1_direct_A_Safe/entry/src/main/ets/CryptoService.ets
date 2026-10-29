import hmcrypto from 'libhmcrypto.so';
import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let rawBuf = hmcrypto.deriveSessionKeyBridge();
    let payload = new Uint8Array(rawBuf);
    let outPayload = payload;
    let cipher = cryptoFramework.createCipher('SM4_128|CBC|PKCS7');
    outPayload.fill(0);
  }

}
