# cve_for_today
A script to fetch today new update cve info

一个用于获取[当天更新的CVE脚本](https://cassandra.cerias.purdue.edu/CVE_changes/today.html)，因为当日更新的CVE，NVD并没有定漏洞等级和评分，可以自己修改脚本去掉不要的或者加上自己想要的，这个脚本也是在之前的脚本上修改的。

想法源自[煜阳yuyang](https://www.freebuf.com/articles/es/228571.html)的这篇文章，感谢[steward007](<https://github.com/steward007>)的建议。

## Preface

```python
# pip3 install -i https://pypi.douban.com/simple/ -r requirements.txt
```

## Sample

```python
# python3 fetch_cves.py
[1/68]CVE-2017-18697
https://nvd.nist.gov/vuln/detail/CVE-2017-18697
v3 not scored, switch to v2...
v2 not scored either...
----------------------------------
编号： CVE-2017-18697
漏洞描述： 
漏洞等级： N/A
漏洞评分： N/A
...
```



获取某个特定版本软件的漏洞统计信息，请参考[vul-info-collect](https://github.com/starnightcyber/vul-info-collect).

![image](https://github.com/starnightcyber/cve_for_today/blob/master/cves.png)
