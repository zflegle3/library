const myLibrary = [];


function Book(title, author, pages, readYN) {
    this.title = title;
    this.author = author;
    this.pages = pages;
    //need if case to handle y/n and populate readYN w/ boolean value
    this.readYN = readYN;
    let lower = readYN.toLowerCase();
    if (lower === "y") {
        this.readYN = true;
    } else if (lower === "n") {
        this.readYN = false;
    } else {
        this.readYN = "Error, Delete book and repopulate field with y or n."
    }
    this.index = myLibrary.length; 
    //object added to end of array so index is length of library prior to adding object
}

Book.prototype.sayInfo = function() {
    console.log(`${this.title} by ${this.author}, is ${this.pages} pages, and ${this.readYN}`);
}

function addBookToLibrary() {
    //Takes user input for title, author, pages, and read(Y/N)
    let tempTitle = prompt("What is the title of the book?","The Old Man and the Sea");
    let tempAuthor = prompt("Who is the Author of this book?","Ernest Hemmingway");
    let tempPages = prompt("How many pages was this book?","420");
    let tempReadYN = prompt("Have you read this book?","y/n");
    //Calls Book constructor to create new book object with user input values
    let tempBook = new Book(tempTitle, tempAuthor, tempPages, tempReadYN);
    //Adds new book object to end of library array 
    myLibrary.push(tempBook);
    updateDisplay()
    console.log(tempReadYN)
}

function updateDisplay() {
    //iterates through objects in library & creates new div objects to display book info
    clearLibrary(); //clears old book div elements before repopulating
    for (i=0; i < myLibrary.length; i++) {
        //Selects keys in current(i) Book Object
        let tempBookVars = Object.keys(myLibrary[i]);
        //Creates Div container element and set class/id 
        let bookDivTemp = document.createElement("div");
        bookDivTemp.setAttribute("class","book-info-card");
        bookDivTemp.setAttribute("id",`${myLibrary[i].index}`);
        //Creates and append p elements with book data 
        for (j=0; j < 3 ; j++) {  //tempBookVars.length
            let pTemp = document.createElement("p");
            let textTemp = document.createTextNode(`${tempBookVars[j]}: ${myLibrary[i][`${tempBookVars[j]}`]}`);
            pTemp.appendChild(textTemp);
            //Append p element to div element
            bookDivTemp.appendChild(pTemp);
        }
        //Creates Remove button and append to book div element
        let newRemoveBtn = createBtn("remove",myLibrary[i])
        bookDivTemp.appendChild(newRemoveBtn);
        //Creates Read button and append to book div element
        let newReadBtn = createBtn("read",myLibrary[i])
        bookDivTemp.appendChild(newReadBtn);
        //Appends book info div element to container div element 
        libraryContainer.appendChild(bookDivTemp);
    }
    updateBtns(); //repopulates event listeners on read/remove buttons
}

function createBtn(btnType,selectedBookObject) {
    //Creates a remove or read button element depending on variables input
    if (btnType === "remove") {
        let tempBtn = document.createElement("button");
        //class and id for query selectors & remove functionality
        tempBtn.setAttribute("class","remove-btn");
        tempBtn.setAttribute("id",`${selectedBookObject.index}`);
        tempBtn.appendChild(document.createTextNode("Remove"));
        return tempBtn; //returns back button element
    } else if (btnType === "read") {
        let tempBtn = document.createElement("button");
        //class and id for query selectors & toggle style functionality
        tempBtn.setAttribute("id",`${selectedBookObject.index}`);
        if (selectedBookObject.readYN) {
            tempBtn.setAttribute("class","read-btn read-yes");
            tempBtn.appendChild(document.createTextNode("Read"));
        } else {
            tempBtn.setAttribute("class","read-btn read-no");
            tempBtn.appendChild(document.createTextNode("Not Read"));
        }
        return tempBtn; //returns back button element
    } 
}

function updateBtns() {
    //Adds event listeners on buttons once display is updated
    //Remove Buttons
    let removeBtns = document.querySelectorAll(".remove-btn");
    for (const rmButton of removeBtns) {
        rmButton.addEventListener("click",removeBookToLibrary);
      }
    //Read Buttons
    let readBtns = document.querySelectorAll(".read-btn");
    for (const readButton of readBtns) {
        readButton.addEventListener("click",readToggle);
      }


}

function removeBookToLibrary(e) {
    //removes book from library array //
    myLibrary.splice(e.srcElement.id,1)
    //removes all dom elements from book library
    clearLibrary()
    //updates indexes of objects and buttons in library 
    for (i=0; i < myLibrary.length; i++) {
        myLibrary[i].index = i;
    }
    //Calls update display to repopulate book divs 
    updateDisplay()
}

function clearLibrary() {
    //removes all elements from library container div
    while (libraryContainer.firstChild) {
        let tempRemoveDiv = libraryContainer.firstChild;
        while (tempRemoveDiv.firstChild) {
            tempRemoveDiv.removeChild(tempRemoveDiv.firstChild);
        }
        libraryContainer.removeChild(libraryContainer.firstChild);
    }
}

function readToggle(e) {
    console.log(e);
    let btnSelected = e.srcElement
    let classes = btnSelected.classList;
    //toggle class for button to change display of button 
    let yesTog = classes.toggle("read-yes");
    let noTog = classes.toggle("read-no");
    //console.log(yesTog);
    console.log(btnSelected);

    //update object value
    if (yesTog) {
        myLibrary[e.srcElement.id].readYN = true;
      } else {
        myLibrary[e.srcElement.id].readYN = false;
      }

    //change text content of button
    if (yesTog) {
        btnSelected.textContent = "Read";
      } else {
        btnSelected.textContent = "Not Read";
      }

}
  

//initial test cases
const book1 = new Book("Dune","Frank Herbert",420,"y");
myLibrary.push(book1);
const book2 = new Book("The Catcher in the Rye","J.D. Salinger", 241,"n");
myLibrary.push(book2);
const book3 = new Book("The Hitchhiker's Guide to the Galaxy","Douglas Adams", 208,"y");
myLibrary.push(book3);


//event listener for buttons
const newBtn = document.querySelector(".new-btn");
const libraryContainer = document.querySelector(".library-container");
newBtn.addEventListener("click",addBookToLibrary);


