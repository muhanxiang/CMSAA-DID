package main

import (
	"backend/model/cmsaa"
	"fmt"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	pairing := cmsaa.Generate(160, 512)
	fmt.Println("g1 =", pairing.G1)
	fmt.Println("g2 =", pairing.G2)
	fmt.Println("h1 =", pairing.H1)
	fmt.Println("h2 =", pairing.H2)

}
