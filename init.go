package main

import (
	"fmt"
)

const MAX = 30
const MAX_INTERACTIONS = 50

type Pessoa struct {
	id    int32
	nome  string
	idade int32
}

func mostraPessoa(pessoas []Pessoa) {
	fmt.Printf("\n=========== Pessoas cadastradas ===========")
	fmt.Println()

	for i := 0; i < len(pessoas); i++ {
		if pessoas[i].idade == 0 {
			break
		}

		fmt.Printf("\n======================")
		fmt.Print("\nID: ")
		fmt.Print(pessoas[i].id)

		fmt.Print("\nNome: ")
		fmt.Print(pessoas[i].nome)

		fmt.Print("\nIdade: ")
		fmt.Print(pessoas[i].idade)
		fmt.Printf("\n======================")

		fmt.Println()

	}
}

func adicionarPessoa(pessoas []Pessoa) {
	var i int32 = 0

	for ; i < MAX; i++ {
		if pessoas[i].idade == 0 {
			pessoas[i].id = i + 1
			fmt.Printf("Insira o nome da pessoa na posição: %v\n", i)
			fmt.Scan(&pessoas[i].nome)

			fmt.Printf("Insira a idade da pessoa na posição: %v\n", i)
			fmt.Scan(&pessoas[i].idade)

			fmt.Printf("\n%v adicionado(a)", pessoas[i].nome)
			fmt.Println()
			break
		}
	}

}

func deletarPessoa(pessoas []Pessoa, id int32) {
	var i int32 = 0
	var nome string = ""

	for ; i < MAX; i++ {
		if pessoas[i].id == id {
			nome = pessoas[i].nome
			pessoas[i].id = 0
			pessoas[i].nome = ""

			pessoas[i].idade = 0

			fmt.Printf("\n%v exluido(a)", nome)
			fmt.Println()
			break
		}
	}
}

func atualizarPessoa(pessoas []Pessoa, id int32, novoNome string, novaIdade int32) {
	var i int32 = 0
	var nome string = ""

	for ; i < MAX; i++ {
		if pessoas[i].id == id {

			if novoNome == "" || novoNome == "0" {
				novoNome = pessoas[i].nome
			}

			if novaIdade == 0 {
				novaIdade = pessoas[i].idade
			}

			pessoas[i].nome = novoNome
			pessoas[i].idade = novaIdade
			nome = pessoas[i].nome

			fmt.Printf("\n Informações de %v atualizadas!", nome)
			fmt.Println()
			break
		}
	}
}

func showOptions() {
	fmt.Println("\n\n\n=========== CADASTRADOR DE PESSOAS =============")
	fmt.Println("\n===========       OPÇÔES           =============")
	fmt.Print()
	fmt.Println("[0] SAIR")
	fmt.Print()
	fmt.Println("[1] ADICIONAR PESSOA")
	fmt.Print()
	fmt.Println("[2] ATUALIZAR INFORMAÇÔES DA PESSOA")
	fmt.Print()
	fmt.Println("[3] EXCLUIR PESSOA DA LISTA")
	fmt.Print()
	fmt.Println("[4] VER TODAS AS PESSOAS CADASTRADAS")
	fmt.Print()

}

func interactiveMenu(pessoas []Pessoa, option int16) {

	if option == 1 {
		adicionarPessoa(pessoas)
	}
	if option == 2 {
		var novoNome string = ""
		var novaIdade int32 = 0
		var id int32 = 0

		fmt.Println("Insira o ID da pessoa (obrigatório): ")
		fmt.Scan(&id)

		fmt.Println("Insira o novo nome (ou  0 enter para pular): ")
		fmt.Scan(&novoNome)

		fmt.Println("Insira a nova idade (ou 0 enter para pular): ")
		fmt.Scan(&novaIdade)

		atualizarPessoa(pessoas, id, novoNome, novaIdade)
	}
	if option == 3 {
		var id int32 = 0

		fmt.Println("Insira o novo nome (obrigatório): ")
		fmt.Scan(&id)
		deletarPessoa(pessoas, id)
	}
	if option == 4 {
		mostraPessoa(pessoas)
	}

}

func cadastraUsuarios() {
	var option int16 = -1
	pessoas := [MAX]Pessoa{}

	for i := 0; i < MAX_INTERACTIONS || option == 0; i += 1 {
		showOptions()
		fmt.Scan(&option)
		interactiveMenu(pessoas[:], option)
	}
}
