import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stepTransform(inputItem: Object): Object {
    let payload = inputItem;
    let b64Helper = new util.Base64Helper();
    let outPayload = b64Helper.encodeToStringSync(payload);
    return outPayload;
  }

  private stepCommit(pref: preferences.Preferences, finalItem: Object): void {
    let outPayload = finalItem;
    pref.putSync('saved_key_ref', outPayload);
  }

  public executeTask(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let publicConfigAlias = symGen.generateSymKeySync();
    let encodedBlob = publicConfigAlias.getEncoded();
    let payload = encodedBlob.data;
    let mid = this.stepTransform(payload);
    this.stepCommit(pref, mid);
  }

}
