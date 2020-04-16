# URL Feature extractor


Feature extractor from the paper **Federated Learning For Cyber Security: SOC Collaboration For Malicious URL Detection**

A code to extract lexicographical features from URLs. Takes as an input the csv file with different URLs and generates 72 features per URL.

The resulting extracted features from the dataset with more than 700K malicious and benign URLs can be found in the archive urls_final_complete.tar.xz . 

Initial URL dataset represents a collection from different sources. The urls are destributed between malware, defacement, phishing, spam and benign classes. They are taken from different sources, in particular from 
[ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html), that was further augmented by:

1. Benign: [Hacker News](https://kaggle.com/hacker-news/hacker-news-posts), [PhishStorm](https://research.aalto.fi/en/datasets/phishstorm--phishing--legitimate-url-dataset(f49465b2-c68a-4182-9171-075f0ed797d5).html), [Ebbu2017 Dataset](https://github.com/ebubekirbbr/pdd/tree/master/input)
2. Malware: [URLHaus](https://urlhaus.abuse.ch/)
3. Phishing: [Openphish](https://openphish.com/), [PhishTank](https://www.phishtank.com/)

Resulting collection of URLs can be found [here](https://www.dropbox.com/s/f9xarvcp4omay38/data.tar.xz?dl=0)

For more details on class distribution, as well as our other experiments please conult the paper. 



