const COS = require('cos-nodejs-sdk-v5');
const base64Url = require('base64-url');
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { TENCENT } = require('config');

const app = express();

app.use(cors({ credentials: true, origin: 'http://127.0.0.1:5500' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.post('/hls/token', (req, res) => {
    try {
        const { token, authorization } = getToken2({ 
            publicKey: req.body.publicKey, 
            bucket: TENCENT.bucket, 
            src: req.body.src
        })

        res.send({ message: 'ok', token });
    } catch (error) {
        console.log(error);
    }
});

function getToken2({ publicKey, bucket, src }) {
    const srcReg = /^https?:\/\/([^/]+)\/([^?]+)/;
    const appId = bucket.slice(bucket.lastIndexOf('-') + 1);
    const m = src.match(srcReg);
    const pathKey = m[2];

    try {
        const header = {
            "alg": "HS256",
            "typ": "JWT"
        }

        const payload = {
            Type: 'CosCiToken',
            AppId: appId,
            BucketId: bucket,
            Issuer: 'client',
            IssuedTimeStamp: 1722421700,
            ProtectSchema: 'rsa1024',
            PublicKey: publicKey,
            ProtectContentKey: 1,
            UsageLimit: 100,
            Object: pathKey,
        };

        const Header = base64Url.encode(JSON.stringify(header))
        const PayLoad = base64Url.encode(JSON.stringify(payload))
        const hash = crypto.createHmac('sha256', TENCENT.playKey).update(Header + "." + PayLoad).digest();
        const Signature = base64Url.encode(hash);
        const token = Header + '.' + PayLoad + '.' + Signature

        const authorization = COS.getAuthorization({
            SecretId: TENCENT.secretId,
            SecretKey: TENCENT.secretKey,
            Method: 'get',
            Pathname: `/${pathKey}`,
            Query: {'ci-process': 'pm3u8'},
        });
        
        return { token, authorization };
    } catch (error) {
        throw error
    }
}

app.listen(3000,() =>{
    console.log('app is listening at http://127.0.0.1:3000');
});