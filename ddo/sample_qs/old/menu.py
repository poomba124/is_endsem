# -----------------------------------------------------------------------------
# A flexible and expandable menu-driven program outline in Python.
#
# To add a new feature:
# 1. Define a new function for your feature (e.g., `def new_feature():`).
# 2. Add a new print statement in the `display_menu()` function for the option.
# 3. Add a new `elif` condition in the main loop to call your new function.
# -----------------------------------------------------------------------------

def feature_one():
    """
    Placeholder for your first feature.
    - Add your code for this feature here.
    - It can be a simple print statement or a complex series of operations.
    """
    print("\n--- Feature One Executed ---")
    # Example: Get user input and process it
    try:
        name = input("What is your name? ")
        print(f"Hello, {name}! This is Feature One.")
    except Exception as e:
        print(f"An error occurred: {e}")
    print("-" * 28 + "\n")


def feature_two():
    """
    Placeholder for your second feature.
    - You can call other functions, work with files, or do any other task.
    """
    print("\n--- Feature Two Executed ---")
    # Example: Perform a simple calculation
    try:
        num1 = float(input("Enter the first number: "))
        num2 = float(input("Enter the second number: "))
        print(f"The sum of {num1} and {num2} is: {num1 + num2}")
    except ValueError:
        print("Invalid input. Please enter valid numbers.")
    except Exception as e:
        print(f"An error occurred: {e}")
    print("-" * 28 + "\n")


# --- Add more feature functions here as needed ---
# def feature_three():
#     print("\n--- Feature Three Executed ---\n")


def display_menu():
    """
    Displays the main menu options to the user.
    """
    print("==============================")
    print("      MAIN MENU")
    print("==============================")
    print("1. Run Feature One")
    print("2. Run Feature Two")
    # Add new menu options here
    # print("3. Run Feature Three")
    print("0. Exit")
    print("------------------------------")


def main():
    """
    The main function that runs the menu loop.
    """
    while True:
        display_menu()
        try:
            choice = input("Enter your choice (0-2): ")

            if choice == '1':
                feature_one()
            elif choice == '2':
                feature_two()
            # Add calls to your new functions here
            # elif choice == '3':
            #     feature_three()
            elif choice == '0':
                print("\nExiting the program. Goodbye!")
                break  # Exit the while loop
            else:
                print("\nInvalid choice. Please enter a number from the menu.\n")

        except KeyboardInterrupt:
            print("\n\nProgram interrupted by user. Exiting...")
            break
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}\n")


# The following block ensures that the main() function is called only when
# the script is executed directly (not when imported as a module).
if __name__ == "__main__":
    main()
