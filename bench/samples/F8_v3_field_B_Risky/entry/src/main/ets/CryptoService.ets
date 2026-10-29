import hmcrypto from 'libhmcrypto.so';
import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let copyAb = hmcrypto.acquireKeyBuffer();
    let payload = copyAb;
    let outPayload = payload;
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    // 仅清零了 ArkTS 副本，Native 原件因使用普通 memset 在 -O2 下被消除而残留
    outPayload.fill(0);
  }

}
