# xterio_palio

xterio 任务

## config

account.txt 填写账号，格式：地址,私钥 一行一个 （注意用英文逗号）不要有多余的空行
proxies.txt 填写代理 格式：user:password@ip:port 一行一个，与账号对应，没有的话不填

## run

```commandline
pip install -r requirements.txt
python xterio.py
```

## note

1. 336行 随机deposit 0.015-0.02的金额到xterio链，可自行修改。deposit 偶尔会失败，重新跑即可，失败只扣gas
2. 438行 填写邀请码，可改为自己的

## plan

1. 添加chatgpt接口自动生成story

## donate
ERC-20: 0xa1482B19EF1a577bb87bE3BB4EFc4d1bA64f5A45




