fn main() {
	let mut vec_u8: Vec<u8> = vec![];

	for i in 0..128 {
		vec_u8.push(i % (rand::random::<u8>()+1));
	}

	println!("{:?}", vec_u8);
}
