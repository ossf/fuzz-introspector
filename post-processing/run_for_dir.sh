R1="$(find $1 -name "*.data")"
#echo "What we found"
#echo $R1


python3 ./main.py ${R1}
