import pickle
import sys
import os
# this dictionary globally saves all the names
dic = {"train":[],"test":[]}
# how do you want to split the test cases
# put the files in respective directories to do a split
directory_1 = sys.argv[1]
directory_2 = sys.argv[2]
for filename in os.listdir(directory_1):
	with open(os.path.join(directory_1, filename)) as f:
		binaryDict = pickle.load(f)
		for key in binaryDict["functions"].keys():
			dic["train"].append(binaryDict["binary_filename"] + ".pkl#" + key)

for filename in os.listdir(directory_2):
	with open(os.path.join(directory_2, filename)) as f:
		binaryDict = pickle.load(f)
		for key in binaryDict["functions"].keys():
			dic["test"].append(binaryDict["binary_filename"] + ".pkl#" + key)

# we need to save this file with given name
pickle.dump(dic, open("split_func.pkl","wb"))
