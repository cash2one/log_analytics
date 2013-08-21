
mkdir -p $2
python logparse.py $1 $2

echo 'parse done'


for i in $2/*.txt; do
  ln -sf $(pwd)/index.html $2
  head -n 1000 $i | python text2table.py > ${i%.*}.html
done
