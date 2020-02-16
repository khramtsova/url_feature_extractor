import pandas as pd
import math
import re
import numpy as np
from urllib.parse import urlsplit, parse_qsl
import csv

fields_names = ['IsExecutable', 'IsPortEighty', 'ISIpAddressInDomainName', 'IsEmptyArgument',
                'CharacterContinuityRate', 'Spchar_URL', 'Tld',
                'Entropy_Domain', 'Entropy_Extension',

                'Len_URL', "Len_Domain", 'Len_Path', 'Len_Directory',
                'Len_Filename', 'Len_Extension',  'Len_Query', 'Len_Arg',

                'TokenCount_Domain', 'TokenCount_Path',

                'AvrgTokenLen_Domain', 'LongestTokenLen_Domain', 'AvrgTokenLen_Path',

                'Ldl_URL', 'Ldl_Domain', 'Ldl_Directory', 'Ldl_Filename', 'Ldl_Arg',
                'Dld_URL', 'Dld_Domain', 'Dld_Directory', 'Dld_Filename', 'Dld_Arg',

                'Ratio_PathURL', 'Ratio_ArgURL', 'Ratio_ArgDomain',
                'Ratio_DomainURL', 'Ratio_DomainPath', 'Ratio_ArgDirectory',

                'DotsCount_URL',

                'DigitCount_URL', 'DigitCount_Domain', 'DigitCount_Directory',
                'DigitCount_Filename', 'DigitCount_Extension', 'DigitCount_Query',

                'LetterCount_URL', 'LetterCount_Domain', 'LetterCount_Directory',
                'LetterCount_Filename', 'LetterCount_Extension', 'LetterCount_Query',

                'LongestTokenLen_Path', 'LongestVariableValue',
                'LongestWordLength_Domain', 'LongestWordLen_Path',
                'LongestWordLen_Filename', 'LongestWordLen_Arg',

                'Delimeter_URL', 'Delimeter_Domain', 'Delimeter_Path',

                'NumberRate_URL', 'NumberRate_Domain', 'NumberRate_Directory',
                'NumberRate_Filename', 'NumberRate_Extension', 'NumberRate_Query',

                'SymbolCount_URL', 'SymbolCount_Domain', 'SymbolCount_Directory',
                'SymbolCount_Filename', 'SymbolCount_Extension', 'SymbolCount_Query',

                'URL_Type_obf_Type']

def read_csv():
    file = pd.read_csv("data/DefacementSitesURLFiltered.csv", low_memory=False, nrows=40)
    print(file.values[0][0], len(file.values[0][0]))
    print(file.values[39][0], len(file.values[39][0]))
    file2 = pd.read_csv("data/All.csv", low_memory=False, nrows=40)
    print(file2["Len_URL"][0])
    print(file2["Len_URL"][39])
    return file


def _get_entropy(string):

    # just from counts
    prob = [float(string.count(char)) / len(string) for char in dict.fromkeys(list(string))]
    # Shannon
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy


class URL:
    def __init__(self, url):
        self.features = dict.fromkeys(fields_names)

        self.url_str = url
        if len(url.split("//")) == 1:
            url = "http://" + url
        self.url = urlsplit(url)
        self.url_length = len(url)

        # My version (More correct)
        temp = self.url.path.split("/")
        self.filename = ''
        self.extension = ''

        # If there is a file in the end
        if temp[-1]:
            splt = temp[-1].split('.')
            # If there is an extension
            if len(splt) > 1:
                # If the extension only consists of numbers and characters
                if re.search(r'^[a-zA-Z0-9\s]*$', splt[-1]):
                    self.extension = splt[-1]
                    splt = splt[:-1]
            self.filename = '.'.join(splt)
            temp = temp[:-1]

        self.directory = ''.join(temp)
        self.query = {}
        self.features["IsEmptyArgument"] = 0
        if self.url.query:
            arguments = self.url.query.split("&")

            for arg in arguments:
                try:
                    indx, value = arg.split("=")
                    # Only = in the end
                    if not value:
                        self.features["IsEmptyArgument"] = 1
                    else:
                        self.query[indx] = value

                except ValueError:
                    # If there are many =
                    if isinstance(arg,list):
                        indx = arg[0]
                        value = ''.join(arg[1:])
                        self.query[indx] = value
                    else:
                        self.features["IsEmptyArgument"] = 1


        #print("host",self.url.hostname)
        #print("path", self.url.path)
        #print(self.url.scheme)
        #print("directory", self.directory)
        #print("filename", self.filename)
        #print("Extension", self.extension)
        #print("Arguments", self.query)
        #raise()



    def create_the_rest(self):
        """
        'Dld_URL', 'Dld_Domain', 'Dld_Directory',
       'Dld_Filename', 'Dld_Arg'
        """
        self.features["Tld"] = len(self.url.hostname.split("."))
        self.features["IsPortEighty"] = (1 if self.url.port == "8080" else 0)
        self.features["DotsCount_URL"] = self.url_str.count('.')
        self.features["ISIpAddressInDomainName"] = 1 if re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", self.url.hostname) else 0

        # CharacterContinuityRate: Character Continuity Rate is used to find the sum
        # of the longest token length of each character type in the domain, such as
        # abc567ti = (3 + 3 + 1)/9 = 0.77. Malicious websites use URLs which have
        # variable number of character types. Character continuity rate determine the
        # sequence of letter, digit and symbol characters.
        try:
            letter_max_count = max([len(i) for i in re.findall(r'[A-Za-z]+', self.url.hostname)])
        except ValueError:
            letter_max_count = 0
        try:
            digit_max_count = max([len(i) for i in re.findall(r'[0-9]+', self.url.hostname)])
        except ValueError:
            digit_max_count = 0

        try:
            characters_max_count = max([len(i) for i in re.findall(r'[\[.:/?=;\\,()\]+&]+', self.url.hostname)])
        except ValueError:
            characters_max_count = 0

        self.features["CharacterContinuityRate"] = (letter_max_count +
                                                    digit_max_count +
                                                    characters_max_count)/len(self.url.hostname)
        self.features["LongestWordLength_Domain"] = letter_max_count

        # ToDo: check IsExecutable
        if self.extension == "exe":
            self.features["IsExecutable"] = 1
        else:
            self.features["IsExecutable"] = 0

        #self.features["charcompace"] = 100
        #char = "aeiouy"
        #self.features["charcompvowels"] = sum(self.url_str.lower().count(x) for x in char)
        #self.features["charcompvowels"] -= sum(self.url.hostname.lower().count(x) for x in char)

    def create_token_features(self):
        "TokenCount_Domain"
        self.features["TokenCount_Domain"] = len(re.findall(r'\w+', self.url.hostname))
        self.features["AvrgTokenLen_Domain"] = np.mean([len(i) for i in re.findall(r'\w+', self.url.hostname)])
        self.features["LongestTokenLen_Domain"] = max([len(i) for i in re.findall(r'\w+', self.url.hostname)])
        #self.features["LongestWordLength_Domain"] = max([len(re.findall(r'[A-Za-z]+', self.url.hostname))])

        if self.directory:
            self.features["TokenCount_Path"] = len(re.findall(r'\w+', self.url.path))
            self.features["AvrgTokenLen_Path"] = np.mean([len(i) for i in re.findall(r'\w+', self.url.path)])
            self.features["LongestTokenLen_Path"] = max([len(i) for i in re.findall(r'\w+', self.url.path)])
            self.features["LongestWordLen_Path"] = max([len(re.findall(r'[A-Za-z]+', self.url.path))])
        else:
            self.features["TokenCount_Path"] = 0
            self.features["AvrgTokenLen_Path"] = 0
            self.features["LongestTokenLen_Path"] = 0
            self.features["LongestWordLen_Path"] = 0

        # ToDo: Verify LongestWordLen_Filename and LongestWordLen_Arg
        if self.filename:
            self.features["LongestWordLen_Filename"] = max([len(re.findall(r'[A-Za-z]+', ''.join(self.filename)))])
        else:
            self.features["LongestWordLen_Filename"] = 0

        if self.query:
            self.features["LongestWordLen_Arg"] = max([len(re.findall(r'[A-Za-z]+', ''.join(self.query.values())))])
        else:
            self.features["LongestWordLen_Arg"] = 0

    def create_symbol_features(self):
        # SymbolCount, Spchar_URL
        symbols = ['.', ':', '/', '?', '=', ',', ';', '(', ')', '[', ']', '+', "&"]

        def f(substr):
            s = substr.count('://')
            temp_str = substr.replace('://', '')
            s += sum(temp_str.count(x) for x in symbols)
            return s

        self.features["SymbolCount_URL"] = f(self.url_str)
        self.features["SymbolCount_Domain"] = f(self.url.hostname)
        self.features["SymbolCount_Directory"] = f(self.directory)
        self.features["SymbolCount_Filename"] = f(''.join(self.filename))
        self.features["SymbolCount_Extension"] = f(''.join(self.extension))
        self.features["SymbolCount_Query"] = f(''.join(self.query.values()))

        # Counts "/"
        def dash_count(substr):
            s = substr.count('://')
            temp_str = substr.replace('://', '')
            s += temp_str.count('/')
            return s
        self.features["Spchar_URL"] = dash_count(self.url_str)


    def create_count_features(self):
        # DigitCount, LetterCount, NumberRate, delimeter

        self.features["DigitCount_URL"] = sum(i.isdigit() for i in self.url_str)
        self.features["DigitCount_Domain"] = sum(i.isdigit() for i in self.url.hostname)
        # Number Rates: Number rate calculate the proportion of digits in the URL parts
        self.features['NumberRate_URL'] = self.features["DigitCount_URL"] / self.url_length
        self.features['NumberRate_Domain'] = self.features["DigitCount_Domain"] / len(self.url.hostname)

        if self.query:
            self.features["DigitCount_Query"] = sum(i.isdigit() for i in ''.join(self.query.values()))
        else:
            self.features["DigitCount_Query"] =0

        if self.directory:
            self.features["DigitCount_Directory"] = sum(i.isdigit() for i in self.directory)
            self.features['NumberRate_Directory'] = self.features["DigitCount_Directory"] / len(self.directory)
        else:
            self.features["DigitCount_Directory"] = 0
            self.features['NumberRate_Directory'] = 0

        if self.filename:
            self.features["DigitCount_Filename"] = sum(i.isdigit() for i in ''.join(self.filename))
            self.features['NumberRate_Filename'] = self.features["DigitCount_Filename"] / len(''.join(self.filename))
        else:
            self.features["DigitCount_Filename"] = 0
            self.features['NumberRate_Filename'] = 0

        if self.extension:
            self.features["DigitCount_Extension"] = sum(i.isdigit() for i in ''.join(self.extension))
            self.features['NumberRate_Extension'] = self.features["DigitCount_Extension"] / len(''.join(self.extension))
        else:
            self.features["DigitCount_Extension"] = 0
            self.features['NumberRate_Extension'] = 0

        if self.query.values():
            self.features['NumberRate_Query'] = self.features["DigitCount_Query"] / len(''.join(self.query.values()))
        else:
            self.features['NumberRate_Query'] = 0

        self.features["LetterCount_URL"] = sum(i.isalpha() for i in self.url_str)
        self.features["LetterCount_Domain"] = sum(i.isalpha() for i in self.url.hostname)
        self.features["LetterCount_Directory"] = sum(i.isalpha() for i in self.directory)
        self.features["LetterCount_Filename"] = sum(i.isalpha() for i in ''.join(self.filename))
        self.features["LetterCount_Extension"] = sum(i.isalpha() for i in ''.join(self.extension))
        self.features["LetterCount_Query"] = sum(i.isalpha() for i in ''.join(self.query.values()))

        # ToDo: Check
        self.features["Delimeter_URL"] = self.url_str.count("-")
        self.features["Delimeter_Domain"] = self.url.hostname.count("-")
        self.features["Delimeter_Path"] = self.url.path.count("-")


        # Unique Letters instead of just Letter count (MY VERSION)
        """
        mask = [i for i in self.url_str if i.isalpha()]
        self.features["LetterCount_URL"] = len(set(mask))
        mask = [i for i in self.url.hostname if i.isalpha()]
        self.features["LetterCount_Domain"] = len(set(mask))
        mask = [i for i in self.url.path if i.isalpha()]
        self.features["LetterCount_Directory"] = len(set(mask))
        mask = [i for i in ''.join(self.filename) if i.isalpha()]
        self.features["LetterCount_Filename"] = len(set(mask))
        mask = [i for i in ''.join(self.extension) if i.isalpha()]
        self.features["LetterCount_Extension"] = len(set(mask))
        mask = [i for i in ''.join(self.url.query) if i.isalpha()]
        self.features["LetterCount_Query"] = len(set(mask))
        print(self.features["LetterCount_URL"], self.features["LetterCount_Domain"],
              self.features["LetterCount_Directory"], self.features["LetterCount_Filename"],
              self.features["LetterCount_Extension"], self.features["LetterCount_Query"])
        """

    def create_length_features(self):

        self.features["Len_URL"] = self.url_length
        self.features["Len_Domain"] = len(self.url.hostname)
        self.features["Len_Path"] = sum(len(i) for i in self.url.path)
        self.features["Len_Directory"] = sum(len(i) for i in self.directory)
        self.features["Len_Filename"] = len(self.filename)
        self.features["Len_Extension"] = len(self.extension)
        self.features["Len_Arg"] = len(self.url.query)
        self.features["Len_Query"] = sum(len(i) for i in self.query.values())

        try:
            self.features["LongestVariableValue"] = max(len(i) for i in self.query.values())
        except ValueError:
            self.features["LongestVariableValue"] = 0

        # Ratios
        self.features["Ratio_PathURL"] = self.features["Len_Path"] / self.features["Len_URL"]
        self.features["Ratio_ArgURL"] = self.features["Len_Arg"] / self.features["Len_URL"]
        self.features["Ratio_ArgDomain"] = self.features["Len_Arg"] / self.features["Len_Domain"]
        self.features["Ratio_DomainURL"] = self.features["Len_Domain"] / self.features["Len_URL"]
        self.features["Ratio_DomainPath"] = self.features["Len_Path"] / self.features["Len_Domain"]
        if self.features["Len_Path"] and self.features["Len_Path"] != 0:
            self.features["Ratio_ArgDirectory"] = self.features["Len_Arg"] / self.features["Len_Path"]
        else:
            self.features["Ratio_ArgDirectory"] = 0

    def create_dld_ldl(self):
        # ToDo : Check ldl and dld in Phishing (always 0 for now)

        self.features["Ldl_URL"] = len(re.findall(r'[A-Za-z][0-9][A-Za-z]', self.url_str))
        self.features["Ldl_Domain"] = len(re.findall(r'[A-Za-z][0-9][A-Za-z]', self.url.hostname))
        self.features["Ldl_Directory"] = len(re.findall(r'[A-Za-z][0-9][A-Za-z]', self.directory))
        self.features["Ldl_Filename"] = len(re.findall(r'[A-Za-z][0-9][A-Za-z]', ''.join(self.filename)))
        self.features["Ldl_Arg"] = len(re.findall(r'[A-Za-z][0-9][A-Za-z]', ''.join(self.query.values())))

        self.features["Dld_URL"] = len(re.findall(r'[0-9][A-Za-z][0-9]', self.url_str))
        self.features["Dld_Domain"] = len(re.findall(r'[0-9][A-Za-z][0-9]', self.url.hostname))
        self.features["Dld_Directory"] = len(re.findall(r'[0-9][A-Za-z][0-9]', self.directory))
        self.features["Dld_Filename"] = len(re.findall(r'[0-9][A-Za-z][0-9]', ''.join(self.filename)))
        self.features["Dld_Arg"] = len(re.findall(r'[0-9][A-Za-z][0-9]', ''.join(self.query.values())))

    def create_entropy(self):
        self.features["Entropy_Domain"] = _get_entropy(self.url.hostname)
        self.features["Entropy_Extension"] = _get_entropy(self.extension)

    def check(self, correct):
        for key, elem in self.features.items():
            if elem:
                if isinstance(correct[key], str):
                    print(key)
                    raise()
                    #correct[key] = float(correct[key])

                if math.isclose(elem, correct[key], rel_tol=1e-05):
                    print(key, correct[key], "Passed")
                    continue
                else:
                    print("Error in ", key, elem, correct[key] )

    def print_result(self):
        for key, elem in self.features.items():
            if elem is  None:
                print(key, elem)


def extract_features_and_write(url_name, writer, attack):
    url = URL(url_name)
    if url.url.hostname:
        url.create_length_features()
        url.create_count_features()
        url.create_symbol_features()
        url.create_token_features()
        url.create_dld_ldl()
        url.create_the_rest()
        url.create_entropy()
        url.features["URL_Type_obf_Type"] = attack
        writer.writerows([url.features])
    else:
        print("TYPO IN", url_str)

    return True


def delete_row_by_value(series, value):
    id_remove = series[series == value].index
    benign_hacker_news_posts.drop(id_remove, inplace=True)
    return True


if __name__ == "__main__":

    phishing = pd.read_csv("data/phishing_dataset.csv", low_memory=False, squeeze=True)
    defacement = pd.read_csv("data/DefacementSitesURLFiltered.csv", low_memory=False, squeeze=True)
    malware = pd.read_csv("data/Malware_dataset.csv", low_memory=False, squeeze=True)
    spam = pd.read_csv("data/spam_dataset.csv", low_memory=False, squeeze=True)
    benign = pd.read_csv("data/Benign_list_big_final.csv", low_memory=False, squeeze=True)

    benign_hacker_news_posts = pd.read_csv("data/new_datasets/HN_posts_year_to_Sep_26_2016.csv", low_memory=False, squeeze=True)

    malware_haus = pd.read_csv("data/new_datasets/malware_urlhaus.csv", sep='delimiter',
                               header=None, names=["url"], engine='python')
    malware_haus = malware_haus[:-70000]["url"]
    openfish = pd.read_csv("data/new_datasets/openphish.csv", squeeze=True)
    phishtank = pd.read_csv("data/new_datasets/PhishTank.csv", squeeze=True)["url"]

    ben2 = pd.read_json("data/new_datasets/data_legitimate_36400.json")[0]

    cols = ["domain", "ranking", "mld_res", "mld.ps_res", "card_rem",
            "ratio_Rrem", "ratio_Arem", "jaccard_RR", "jaccard_RA",
            "jaccard_AR", "jaccard_AA", "jaccard_ARrd", "jaccard_ARrem", "label"]
    radu_ds = pd.read_csv("data/new_datasets/urlset_samuel_radu.csv",
                          names=cols, encoding='latin1', header=None)[1:]
    ben3 = radu_ds[radu_ds["label"] == 0]
    ben3 = ben3.append(radu_ds[radu_ds["label"] == "0.0"])
    ben3 = ben3["domain"]

    print("ALL was read")


    #delete_row_by_value(benign_hacker_news_posts, "http://about:reader?url=http%3A%2F%2Fwww.nextplatform.com%2F2016%2F02%2F04%2Ffuture-systems-what-will-tomorrows-server-look-like%2F")
    #delete_row_by_value(benign_hacker_news_posts, "http:////lineupsongs.com")
    #delete_row_by_value(benign_hacker_news_posts, "http://://www.altmetric.com/blog/reddit-ama-recap-stacy/")
    #delete_row_by_value(benign_hacker_news_posts, "https:///autos/google-pairs-with-ford-to-1326344237400118.html")
    #benign_hacker_news_posts.dropna(inplace=True)
    #benign_hacker_news_posts.drop_duplicates(inplace=True)
    #benign_hacker_news_posts.to_csv("data/HN_posts_year_to_Sep_26_2016.csv", header="url", index=False)

    f = open('data/new_features/urls_final_complete.csv', 'w')
    print(fields_names, "\n")
    writer = csv.DictWriter(f, fieldnames=fields_names)
    writer.writeheader()

    index = 0

    print("Starting with Benign")
    for url_str in benign:
        extract_features_and_write(url_str, writer, "benign")

    for url_str in benign_hacker_news_posts:
        extract_features_and_write(url_str, writer, "benign")

    for url_str in ben2:
        extract_features_and_write(url_str, writer, "benign")

    for url_str in ben3:
        extract_features_and_write(url_str, writer, "benign")
    print("Done with Benign")

    print("Starting with Malware")
    for url_str in malware:
        extract_features_and_write(url_str, writer, 'malware')

    for url_str in malware_haus:
        extract_features_and_write(url_str, writer, 'malware')
    print("Done with Malware")

    print("Starting with Defacement")
    for url_str in defacement:
        extract_features_and_write(url_str, writer, 'defacement')
    print("Done with Defacement")

    print("Starting with Phishing")
    for url_str in phishing:
        extract_features_and_write(url_str, writer, 'phishing')
    for url_str in phishtank:
        extract_features_and_write(url_str, writer, 'phishing')
    for url_str in openfish:
        extract_features_and_write(url_str, writer, 'phishing')
    print("Done with Phishing")

    print("Starting with Spam")
    for url_str in spam:
        extract_features_and_write(url_str, writer, 'spam')
    print("Done with Spam")

    print("\n\n ==============================================")
    """
    
    """
    """/
    # !!! Extended checks !!!

    for id in range(76):
        url_str = file1.values[id]
        correct = file2.iloc[id, :]
        print(url_str)
        url = URL(url_str)
        url.create_count_features()
        url.check(correct)
    print("Checks are preformed")
    """