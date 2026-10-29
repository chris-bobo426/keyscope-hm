import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  private stagingSlot: Object = new Object();

  public prepareStage(pref: preferences.Preferences): void {
    let keyAlias = 'huks_auth_token_alias';
    huks.generateKeyItem(keyAlias, new Object());
    let symGen = cryptoFramework.createSymKeyGenerator('SM4_128');
    let tempKey = symGen.generateSymKeySync();
    let tempBytes = tempKey.getEncoded().data;
    tempBytes.fill(0);
    let metaObj: Record<string, Object> = new Object() as Record<string, Object>;
    metaObj.handleRef = keyAlias;
    let payload = metaObj;
    let outPayload = JSON.stringify(payload);
    this.stagingSlot = outPayload;
  }

  public flushStage(pref: preferences.Preferences): void {
    let outPayload = this.stagingSlot;
    pref.putSync('serialized_meta', outPayload);
  }

}
