const myLibrary = [];

function Book(title, author, pages, readYN) {
    this.title = title;
    this.author = author;
    this.pages = pages;
    this.readYN = readYN;
    this.index = myLibrary.length; 
}

function createUIForm() {
    //Select div element 
    let formIn = document.getElementById("form");
    formIn.classList.toggle("visable")
    //SubmitButton
    let submitBtn = document.getElementById("submit");
    submitBtn.addEventListener("click",submitBookData);
}


function submitBookData(e) {
    e.preventDefault();
    //validate book data
    let bookDataIn = document.querySelectorAll(".form-input");
    let errorMsgs = document.querySelectorAll(".form-error");
    let submitGate = true;
    
    for (let i=0; i<bookDataIn.length; i++) {
        if (!bookDataIn[i].checkValidity()) {
            //prevent submision
            submitGate = false;
            //update error message
            errorMsgs[i].innerHTML = bookDataIn[i].validationMessage
            //toggle error class on input 
            bookDataIn[i].classList = "form-input error";
        } else if(bookDataIn[i].checkValidity()) {
            bookDataIn[i].classList = "form-input valid";
            errorMsgs[i].innerHTML = "";
        }
    }
    if (submitGate) {
        addBookToLibrary(bookDataIn);
        document.getElementById("form").classList.toggle("visable")
        document.getElementById("form").reset();
        for (let i=0; i<bookDataIn.length; i++) {
            bookDataIn[i].classList = "form-input";
        }
    } 
}



function addBookToLibrary(newBookData) {
    //Creates a form to take in user data
    let tempTitle = newBookData[0].value.trim();
    let tempAuthor = newBookData[1].value.trim();
    let tempPages = newBookData[2].value.trim();
    let tempReadN = newBookData[4].checked;
    let tempReadYN = true;
    if (tempReadN) {
        tempReadYN = false;
    }
    //Calls Book constructor to create new book object with user input values
    let tempBook = new Book(tempTitle, tempAuthor, tempPages, tempReadYN);
    //Adds new book object to end of library array 
    myLibrary.push(tempBook);
    updateDisplay()
}

function updateDisplay() {
    //iterates through objects in library & creates new div objects to display book info
    clearDisplayDiv(".library-container"); //clears old book div elements before repopulating
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
    for (let rmButton of removeBtns) {
        rmButton.addEventListener("click",removeBookToLibrary);
      }
    //Read Buttons
    let readBtns = document.querySelectorAll(".read-btn");
    for (let readButton of readBtns) {
        readButton.addEventListener("click",readToggle);
      }


}

function removeBookToLibrary(e) {
    //removes book from library array //
    myLibrary.splice(e.srcElement.id,1)
    //removes all dom elements from book library
    //clearLibrary()
    //updates indexes of objects and buttons in library 
    for (i=0; i < myLibrary.length; i++) {
        myLibrary[i].index = i;
    }
    //Calls update display to repopulate book divs 
    updateDisplay()
}

function clearDisplayDiv(classIn) {
    let divSelected = document.querySelector(classIn);
    //removes all elements from library container div
    while (divSelected.firstChild) {
        let tempRemoveDiv = divSelected.firstChild;
        //while (tempRemoveDiv.firstChild) {
        //    tempRemoveDiv.removeChild(tempRemoveDiv.firstChild);
        //}
        divSelected.removeChild(divSelected.firstChild);
    }
}

function readToggle(e) {
    let btnSelected = e.srcElement;
    let classes = btnSelected.classList;
    //toggle class for button to change display of button 
    let yesTog = classes.toggle("read-yes");
    // let noTog = classes.toggle("read-no");

    //update object read property value & changes text content of button
    if (yesTog) {
        myLibrary[e.srcElement.id].readYN = true;
        btnSelected.textContent = "Read";
      } else {
        myLibrary[e.srcElement.id].readYN = false;
        btnSelected.textContent = "Not Read";
      }
}
  
//initial test cases
// const book1 = new Book("Dune","Frank Herbert",420,true);
// myLibrary.push(book1);
// const book2 = new Book("The Catcher in the Rye","J.D. Salinger", 241,false);
// myLibrary.push(book2);
// const book3 = new Book("The Hitchhiker's Guide to the Galaxy","Douglas Adams", 208,true);
// myLibrary.push(book3);


//event listener for buttons
const newBtn = document.querySelector(".new-btn");
const libraryContainer = document.querySelector(".library-container");
//newBtn.addEventListener("click",addBookToLibrary);
newBtn.addEventListener("click",createUIForm);


