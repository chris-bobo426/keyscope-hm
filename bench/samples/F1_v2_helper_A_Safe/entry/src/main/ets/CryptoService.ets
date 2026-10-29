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
    pref.putSync('saved_key_ref', outPayload);
  }

  public executeTask(pref: preferences.Preferences): void {
    let secretKeyMaterial_8f9a2b3c4d5e6f01 = 'huks_sm4_key_alias_9f8e7d6c5b4a3f2e';
    huks.generateKeyItem(secretKeyMaterial_8f9a2b3c4d5e6f01, new Object());
    let payload = secretKeyMaterial_8f9a2b3c4d5e6f01;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}
