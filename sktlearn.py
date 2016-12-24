from sklearn import datasets
from sklearn import svm

iris = datasets.load_iris()
digits = datasets.load_digits()

clf = svm.SVC(gamma=0.001, C=100.)
clf.fit(digits.data[:-2], digits.target[:-2])
a=clf.predict(digits.data[-2:])
print(a[1])
