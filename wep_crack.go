package main

import (
    "fmt"
    "os"
    "strings"
    "strconv"
    "io/ioutil"
    "flag"
    "math/rand"
)

type IV_encbyte_pair struct {
    IV      []int
    encByte   int
}

// RCC4 cipher state
type RC4 struct {
    S []int
    i int
    j int
    key []int
}

// Sets RC4 in state KSA algorithm upto "rounds" number of rounds
func (rc4 *RC4) KSA (rounds int) {
    rc4.S = make([]int, 256)   // Reset S
    for rc4.i = 0 ; rc4.i<256 ; rc4.i++ {
        rc4.S[rc4.i] = int(rc4.i)
    }

    rc4.j = 0
    for rc4.i = 0 ; rc4.i<rounds ; rc4.i++ {
        rc4.j = (rc4.j + rc4.S[rc4.i] + rc4.key[rc4.i % len(rc4.key)]) % 256

        // Swap S[i] and S[j]
        tmp := rc4.S[rc4.i]
        rc4.S[rc4.i] = rc4.S[rc4.j]
        rc4.S[rc4.j] = tmp
    }
}

func (rc4 *RC4) PRGA_Init ( key []int ) {
    rc4.key = key
    rc4.KSA(256)    // Initialise S
    rc4.i = 0
    rc4.j = 0
}
func (rc4 *RC4) PRGA_NextByte () int {
    rc4.i = (rc4.i + 1) % 256
    rc4.j = (rc4.j + rc4.S[rc4.i]) % 256

    // Swap values of S[i] and S[j]
    tmp := rc4.S[rc4.i]
    rc4.S[rc4.i] = rc4.S[rc4.j]
    rc4.S[rc4.j] = tmp

    K := rc4.S[(rc4.S[rc4.i] + rc4.S[rc4.j]) % 256]
    return K
}

func (rc4 *RC4) getNthKeyByte(IVList []IV_encbyte_pair, n int, guessedKey []int, knownFirstByte int) int {
    voteCount := make([]int, 256)   // vote count to bytes to be the key byte

    for _, iv := range IVList {
        if iv.IV[0] == 3+n && iv.IV[1] == 255 { // Weak IV
            rc4.key = append(iv.IV,guessedKey...)
            rc4.KSA(3+n)
            //fmt.Println("S after 3 rounds : %v", S)

            byteToSearch := knownFirstByte ^ iv.encByte
            for index, b := range rc4.S {
                if b==byteToSearch {
                    keyByte := (index-rc4.j-rc4.S[rc4.i]+256+256) % 256
                    voteCount[keyByte]++
                    break
                }
            }
        }
    }

    maxVote:=0
    predictedKey := 0
    for index, x := range voteCount {
        if x>maxVote {
            maxVote=x
            predictedKey = index
        }
    }

    //fmt.Println("Predicted key: %v with vote %v", predictedKey, maxVote)
    return predictedKey
}


func EncryptBytes (data []byte, passwdBytes []int) []int {
    rc4 := RC4{}
    rc4.PRGA_Init(passwdBytes)

    encBytes := []int{}
    for _,b := range []byte(data) {
        e := int(b)^rc4.PRGA_NextByte()
        encBytes = append(encBytes, e)
    }

    return encBytes
}
func encryptFile(filename string, passwd string, outfile string) {
    writeToFile := func(line string){
        f, err := os.OpenFile(outfile, os.O_APPEND|os.O_WRONLY, 0600)
        if err != nil {
            panic(err)
        }

        defer f.Close()

        if _, err = f.WriteString(line); err != nil {
            panic(err)
        }
    }


    writeToFile(strconv.Itoa(len(passwd)) + "\n")
    //ioutil.WriteFile(*outFileFlag, []byte(strconv.Itoa(len(*passwdFlag))+"\n"), os.ModeAppend)


    file, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println("Input file does not exist : ", err.Error())
        os.Exit(1)
    }

    keySize := len(passwd)
    passwdBytes := make([]int, keySize)
    for i, b := range []byte(passwd) {
        passwdBytes[i] = int(b)
    }
    fmt.Printf("Key is : %v\n", passwdBytes)

    fileContent := string(file)
    fileContent = strings.Trim(fileContent, " \n\r")
    lines := strings.Split(fileContent, "\n")

    for i, line := range lines {
        iv := []int{ 3 + i%keySize, 255, rand.Int()%256}
        encLine := EncryptBytes([]byte(line), append(iv,passwdBytes...))           // Encrypting with iv+passwd
        encLineStr := fmt.Sprintf("%v %v %v", iv[0], iv[1], iv[2])      // Prepending IV
        for _, encb := range encLine {
            encLineStr += " " + strconv.Itoa(encb)
        }

        //fmt.Printf("Plain line     : %v\n", line)
        //fmt.Printf("%v Encrypted line : %v\n", passwdBytes, append(iv,passwdBytes...))

        encLineStr = strings.Trim(encLineStr, " \n\r")
        encLineStr += "\n"
        writeToFile(encLineStr)
        //ioutil.WriteFile(outfile, []byte(encLineStr), os.ModeAppend)
    }
}

func getIvList (encrypted_file string) (IVList []IV_encbyte_pair, keysize int) {
    file, err := ioutil.ReadFile(encrypted_file)
    if err != nil {
        fmt.Println("Input file does not exist : ", err.Error())
        os.Exit(1)
    }
    fileContent := string(file)
    fileContent = strings.Trim(fileContent, " \n\r")

    IVListStr := strings.Split(fileContent, "\n")
    signedInt, _ := strconv.Atoi(IVListStr[0])
    keysize = int(signedInt)
    IVListStr = IVListStr[1:]

    IVList = []IV_encbyte_pair{}
    for _, IVpairStr := range IVListStr {

        // Convert all (IV and first enc byte in uint and append to iv
        iv := []int{}
        for _, bStr := range strings.Split(IVpairStr, " ") {
            bStr = strings.Trim(bStr," \n\r")
            if bStr=="" {
                continue
            }

            b, err := strconv.Atoi(bStr)
            if err!=nil {
                fmt.Println("Error in converting %v to int", bStr)
                os.Exit(2)
            }
            iv = append(iv, b)
        }

        IVEncPair := IV_encbyte_pair{IV:iv[:3], encByte:iv[3]}
        IVList = append(IVList,IVEncPair)
    }

    return IVList, keysize
}


func main() {
    encryptFlag := flag.Bool("e", false, "Encrypt an input file")
    inFileFlag := flag.String("i", "", "Input file")
    outFileFlag := flag.String("o", "out.enc", "Output file")
    passwdFlag := flag.String("p", "", "Password")
    //decryptFlag := flag.Bool("d", true, "Decrypt an input file")
    knownFirstByte := flag.Int("pt", -1, "First byte of known plain text")
    flag.Parse()

    if *inFileFlag == "" {
        fmt.Println("Please provide input file\n")
        flag.Usage()
        os.Exit(1)
    }

    if *encryptFlag {
        if *passwdFlag=="" {
            fmt.Println("Please provide password\n")
            flag.Usage()
            os.Exit(1)
        }

        encryptFile(*inFileFlag, *passwdFlag, *outFileFlag)

        fmt.Printf("File %v encrypted with passwd %v; output:%v\n", *inFileFlag, *passwdFlag, *outFileFlag)
    } else {
        if *knownFirstByte == -1 {
            fmt.Println("Please first plain text byte\n")
            flag.Usage()
            os.Exit(1)
        }

        IVList, keysize := getIvList(*inFileFlag)

        rc4State := RC4{}
        guessedKey := []int{}
        for i:=0 ; i<keysize ; i++ {
            key := rc4State.getNthKeyByte(IVList, i, guessedKey, *knownFirstByte)
            guessedKey = append(guessedKey, key)
        }


        guessedKeyByte := []byte{}
        for _, i := range guessedKey {
            guessedKeyByte = append(guessedKeyByte, byte(i))
        }
        fmt.Println("The key is : ", string(guessedKeyByte))
    }
}
