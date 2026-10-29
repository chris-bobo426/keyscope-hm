import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
    let outPayload = JSON.stringify(payload);
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
    pref.putSync('serialized_meta', outPayload);
  }

  public executeTask(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let tempKey = symGen.generateSymKeySync();
    let tempBytes = tempKey.getEncoded().data;
    let secretContainer: Record<string, Object> = new Object() as Record<string, Object>;
    secretContainer.rawKeyField = tempBytes;
    let payload = secretContainer;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}
