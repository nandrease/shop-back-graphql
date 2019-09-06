const Mutations = {
    createDog(parent, args, ctx, info) {
        global.dogs = global.dogs || []
        //create a dog
        const newDog = { name: args.name }
        global.dogs.push(newDog)
        console.log('create a dog', global.dogs)
        return newDog
    }
};

module.exports = Mutations;
