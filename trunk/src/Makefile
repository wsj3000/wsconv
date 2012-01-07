
build_dir=../build

target=$(build_dir)/wsconv

$(target):$(build_dir) wsconv.c
	gcc wsconv.c -o $(target) -DBLDTM="\"$$(date)\""

$(build_dir):
	if [ ! -d $(build_dir) ]; then  mkdir $(build_dir); fi;
