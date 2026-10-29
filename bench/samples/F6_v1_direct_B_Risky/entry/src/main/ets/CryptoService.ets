import cryptoFramework from '@ohos.security.cryptoFramework';
import huks from '@ohos.security.huks';
import preferences from '@ohos.data.preferences';
import util from '@ohos.util';
import hilog from '@ohos.hilog';

export class CryptoService {
  public executeTask(pref: preferences.Preferences): void {
    let symGen = cryptoFramework.createSymKeyGenerator('AES256');
    let sessionKey = symGen.generateSymKeySync();
    let rawBytes = sessionKey.getEncoded().data;
    let textDec = util.TextDecoder.create('utf-8');
    let reversibleStr = textDec.decodeToString(rawBytes);
    rawBytes.fill(0);
    let payload = reversibleStr;
    let outPayload = payload;
    pref.putSync('key_reversible_backup', outPayload);
  }

}
