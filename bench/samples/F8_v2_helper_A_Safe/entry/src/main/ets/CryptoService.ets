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
    // 对 external_arraybuffer 别名调用 fill(0) 即同步清零了底层共享原件
    outPayload.fill(0);
  }

  public executeTask(pref: preferences.Preferences): void {
    let extAb = hmcrypto.acquireKeyBuffer();
    let payload = extAb;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}
