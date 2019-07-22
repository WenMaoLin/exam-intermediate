const crypto  = require("crypto");
const axios = require("axios");

const url = 'https://easy-mock.com/mock/5bbefdf6faedce31cd6a5261/example/exam-intermediate';

const firstToUpperCase = (string) => {
  return string[0].toUpperCase() + string.slice(1);
}


const checkKeysNotInObject = (source, keys) => {
  const _arr = [];
  keys.forEach(key => {
    if (!source.hasOwnProperty(key)) _arr.push(key);
  });
  return _arr;
}

const checkKeysExistsInObject = (source, keys) => {
  const _arr = [];
  keys.forEach(key => {
    if (source.hasOwnProperty(key)) _arr.push(key);
  });
  return _arr;
}

const paramsToEncodeURL = (params) => {
  let str = [];
  for (var i in params) {
    str.push(`${encodeURIComponent(i)}=${encodeURIComponent(params[i])}`);
  }
  str.sort();
  str = str.join('&');
  str = 'POST&%2F&' + encodeURIComponent(str);
  return str;
}

const generateEncryptionReqBody = (accessKeySecret, content) => {
  const sign = crypto.createHmac("sha1", accessKeySecret + '&')
    .update(content)
    .digest('base64');

  const signature = encodeURIComponent(sign);
  var reqBody = ['Signature=' + signature];

  for (var i in content) {
    reqBody.push(i+'='+content[i]);
  }
  reqBody = reqBody.join('&');

  return reqBody;
};


module.exports = async (config = {}, cb) => {
  const nonce = Date.now();
  const date = new Date();
  const errorMsg = [];

  let basesParams = {
    AccessKeyId: config.accessKeyID,
    Format: 'JSON',
    AccountName: config.accountName,
    AddressType: typeof config.addressType === 'undefined' ? 0 : config.addressType,
    SignatureMethod: 'HMAC-SHA1',
    SignatureNonce: nonce,
    SignatureVersion: '1.0',
    TemplateCode: config.templateCode,
    Timestamp: date.toISOString(),
    Version: '2015-11-23'
  };

  //从 config 对象里面检索对应的key  返回不存在的key 并堆入 errorMsg
  checkKeysNotInObject(config, ['accessKeyID', 'accessKeySecret', 'accountName'])
    .forEach(key => errorMsg.push(`${key} required`));

  
  switch (config.action) {
    case 'single':

      //从 config 对象里面检索对应的key  返回不存在的key 并堆入 errorMsg
      checkKeysNotInObject(config, ['accessKeyID'])
        .forEach(key => errorMsg.push(`${key} required`));

      //参数最终会合并到baseParams
      const params = {
        Action: 'single',
        ReplyToAddress: !!config.replyToAddress,
        ToAddress: config.toAddress,
      };
      //从 config 检索存在的key 加入到params
      checkKeysExistsInObject(config, ['fromAlias', 'subject', 'htmlBody', 'textBody', 'tagName'])
        .forEach(key => params[firstToUpperCase(key)] = config[key] );

      Object.assign(baseParams, params);
      break;


    case 'batch':

      //从 config 对象里面检索对应的key  返回不存在的key 并堆入 errorMsg
      checkKeyNotInObject(config, ['templateName', 'receiversName'])
        .forEach(key => errorMsg.push(`${key} required`));

      const params = {
        Action: 'batch',
        TemplateName: config.templateName,
        ReceiversName: config.receiversName
      };

      //从 config 检索存在的key 加入到params
      checkKeysExistsInObject(config, ['tagName'])
        .forEach(key => params[firstToUpperCase(key)] = config[key] );

      Object.assign(baseParams, params);
      break;
    default:
      return cb('error action', null);
  }

  if (errorMsg.length) {
    return cb(errorMsg.join(','));
  }

  var signStr = paramsToEncodeURL(params);
  const reqBody = generateEncryptionReqBody(config.accessKeySecret + '&', signStr);

  try {
    await axios({
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      uri: url,
      body: reqBody,
      method: 'POST'
    });
  } catch (err) {
    cb(err, err.response);
  }
}