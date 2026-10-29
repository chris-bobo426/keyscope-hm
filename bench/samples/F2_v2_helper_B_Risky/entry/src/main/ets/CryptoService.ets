import hmcrypto from 'libhmcrypto.so';
import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
    let outPayload = payload;
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
    let usedLen = outPayload;
  }

  public executeTask(pref: preferences.Preferences): void {
    let nativeStr = hmcrypto.deriveSessionKeyBridge();
    let payload = nativeStr;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}
