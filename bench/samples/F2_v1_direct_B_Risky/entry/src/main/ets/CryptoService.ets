import hmcrypto from 'libhmcrypto.so';
import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let nativeStr = hmcrypto.deriveSessionKeyBridge();
    let payload = nativeStr;
    let outPayload = payload;
    let usedLen = outPayload;
  }

}
