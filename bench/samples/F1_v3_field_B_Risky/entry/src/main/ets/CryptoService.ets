import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let publicConfigAlias = symGen.generateSymKeySync();
    let encodedBlob = publicConfigAlias.getEncoded();
    let payload = encodedBlob.data;
    let b64Helper = new util.Base64Helper();
    let outPayload = b64Helper.encodeToStringSync(payload);
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    pref.putSync('saved_key_ref', outPayload);
  }

}
