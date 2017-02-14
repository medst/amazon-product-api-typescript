import Sha2 from './sha2';

export class amazonApi {

    public publicKey:string = "your-public-key";
    public secretKey:string = "your-secret-key";
    public associateTag:string = "your-associate-tag";
    public version:string = "2013-08-01";
    public service:string = "AWSECommerceService";
    public host:string = "ecs.amazonaws.com";
    public searchIndex:string = "UnboxVideo";
    public movie:number = 2858905011;
    public tv:number = 2864549011;
    public amazonVideo:number = 2858778011;
    public sha2: Sha2;

    constructor() {
    }

    public itemSearch(keyword, page) {
    let browsenode = this.movie;
    let ResponseGroup = "ItemAttributes";
    let keywords = keyword.replace("'",' ').replace('!', ' ');
    let time = new Date();
    let gmtTime = new Date(time.getTime() + (time.getTimezoneOffset() * 60000));
    let timestap = gmtTime.toISOString();
    let unsignedUrl = "AWSAccessKeyId="+this.publicKey
                + "&Keywords="+keywords
                + "&Operation=ItemSearch"
                + "&SearchIndex="+this.searchIndex
                + "&Service="+this.service
                + "&Timestamp="+timestap
                + "&AssociateTag="+this.associateTag
                + "&Version="+this.version
                + "&BrowseNode="+browsenode
                + "&ResponseGroup="+ResponseGroup
                + "&ItemPage="+page;
    let pairs = unsignedUrl.split("&");
    pairs = this.encodePairs(pairs);
    pairs.sort();
    let canonicalQuery = pairs.join("&");
    let stringToSign = "GET\n" + this.host + "\n/onca/xml\n" + canonicalQuery;
    let signature = this.sign(this.secretKey, stringToSign);
    let signedUrl = "http://" + this.host + "/onca/xml?" + canonicalQuery + "&Signature=" + signature;
    return signedUrl;
  }

  public itemLookup(itemId){
    let ResponseGroup = "ItemAttributes";
    let time = new Date();
    let gmtTime = new Date(time.getTime() + (time.getTimezoneOffset() * 60000));
    let timestap = gmtTime.toISOString();
    let unsignedUrl = "AWSAccessKeyId="+this.publicKey
                + "&ItemId="+itemId
                + "&Operation=ItemLookup"
                + "&Service="+this.service
                + "&IdType=ASIN"
                + "&ResponseGroup="+ResponseGroup
                + "&Timestamp="+timestap
                + "&AssociateTag="+this.associateTag
                + "&Version="+this.version;
    let pairs = unsignedUrl.split("&");
    pairs = this.encodePairs(pairs);
    pairs.sort();
    let canonicalQuery = pairs.join("&");
    let stringToSign = "GET\n" + this.host + "\n/onca/xml\n" + canonicalQuery;
    let signature = this.sign(this.secretKey, stringToSign);
    let signedUrl = "http://" + this.host + "/onca/xml?" + canonicalQuery + "&Signature=" + signature;
    return signedUrl;
    }

  public encodePairs(pairs){
    let name = "";
    let value = ""; 
    for (var i = 0; i < pairs.length; i++) { 
      let pair = pairs[i];
      let index = pair.indexOf("=");
      name = pair.substring(0, index);
      value = pair.substring(index + 1);
      name = encodeURIComponent(decodeURIComponent(name));
	    value = value.replace(/\+/g, "%20");
      value = encodeURIComponent(decodeURIComponent(value));
      pairs[i] = name + "=" + value;
    }  
    return pairs;
  }

  public sign(secret, message) {
    let messageBytes = this.sha2.str2binb(message);
    let secretBytes = this.sha2.str2binb(secret);
    if (secretBytes.length > 16) {
      secretBytes = this.sha2.core_sha256(secretBytes, secret.length * this.sha2.chrsz);
    } 
    let ipad = Array(16), opad = Array(16);
    for (var i = 0; i < 16; i++) { 
      ipad[i] = secretBytes[i] ^ 0x36363636;
      opad[i] = secretBytes[i] ^ 0x5C5C5C5C;
    }
    let imsg = ipad.concat(messageBytes);
    let ihash = this.sha2.core_sha256(imsg, 512 + message.length * this.sha2.chrsz);
    let omsg = opad.concat(ihash);
    let ohash = this.sha2.core_sha256(omsg, 512 + 256);
    let b64hash = this.sha2.binb2b64(ohash);
    let urlhash = encodeURIComponent(b64hash); 
    return urlhash;
  }
}
