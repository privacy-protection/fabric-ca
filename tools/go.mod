module tools

go 1.14

require (
	github.com/AlekSi/gocov-xml v0.0.0-20190121064608-3a14fb1c4737
	github.com/axw/gocov v1.0.0
    github.com/hyperledger/fabric-ca v1.5.0
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de
	golang.org/x/tools v0.0.0-20200131233409-575de47986ce
)

replace (
	github.com/hyperledger/fabric-ca => ../
    github.com/privacy-protection/common => ../../common
    github.com/privacy-protection/cp-abe => ../../cp-abe
)