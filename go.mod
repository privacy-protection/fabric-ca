module github.com/hyperledger/fabric-ca

go 1.15

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/btcsuite/btcd v0.22.1 // indirect
	github.com/ethereum/go-ethereum v1.9.0
	github.com/felixge/httpsnoop v1.0.1
	github.com/go-kit/kit v0.7.0
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/golang/protobuf v1.5.2
	github.com/google/certificate-transparency-go v1.0.21
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grantae/certinfo v0.0.0-20170412194111-59d56a35515b
	github.com/jmhodges/clock v0.0.0-20160418191101-880ee4c33548
	github.com/jmoiron/sqlx v1.2.0
	github.com/kisielk/sqlstruct v0.0.0-20201105191214-5f3e10d3ab46
	github.com/lib/pq v1.8.0
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.5
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.3.3
	github.com/onsi/ginkgo v1.14.2
	github.com/onsi/gomega v1.10.3
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.5.0
	github.com/privacy-protection/common v1.9.1
	github.com/privacy-protection/cp-abe v1.9.1
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/procfs v0.2.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.7.0
	github.com/sykesm/zap-logfmt v0.0.4
	github.com/weppos/publicsuffix-go v0.5.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20190729165852-9051775e6a2e
	github.com/zmap/zlint v0.0.0-20190806154020-fd021b4cfbeb
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20201117144127-c1f2f97bffc9
	golang.org/x/net v0.0.0-20201006153459-a7d1128ccaa0
	golang.org/x/sys v0.0.0-20201015000850-e3ed0017c211 // indirect
	golang.org/x/tools v0.0.0-20200103221440-774c71fcf114
	google.golang.org/grpc v1.26.0
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/ldap.v2 v2.5.1
)

replace (
	github.com/privacy-protection/common => ../common
	github.com/privacy-protection/cp-abe => ../cp-abe
)
