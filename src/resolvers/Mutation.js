const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');

const Mutations = {
	async createItem(parent, args, ctx, info) {
		// TODO: Check if user is logged in

		const item = await ctx.db.mutation.createItem(
			{
				data: {
					...args
				}
			},
			info
		);

		return item;
	},
	updateItem(parent, args, ctx, info) {
		//first take a copy of the updates
		const updates = { ...args };
		// remove the ID that we cannot chante
		delete updates.id;
		//run the update methdod
		return ctx.db.mutation.updateItem(
			{
				data: updates,
				where: {
					id: args.id
				}
			},
			info
		);
	},
	async deleteItem(parent, args, ctx, info) {
		const where = { id: args.id };
		//1. find the item
		const item = await ctx.db.query.item({ where }, `{ id title user { id }}`);
		//2. check if they own the permissions
		const ownsItem = item.user.id === ctx.request.userId;
		const hasPermissions = ctx.request.user.permissions.some((permission) =>
			[ 'ADMIN', 'ITEMDELETE' ].includes(permission)
		);
		if (!ownsItem && !hasPermissions) {
			throw new Error("You don't have permission to do that!");
		}
		//3. Delete item
		return ctx.db.mutation.deleteItem({ where }, info);
	},
	async signUp(parent, args, ctx, info) {
		args.email = args.email.toLowerCase();
		// hash their password
		const password = await bcrypt.hash(args.password, 10);
		// create the user in the database
		const user = await ctx.db.mutation.createUser(
			{
				data: {
					...args,
					password,
					permissions: { set: [ 'USER' ] }
				}
			},
			info
		);
		// create the JWT token
		const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
		// We set the jwt as a cookie on the response
		ctx.response.cookie('token', token, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
		});
		// Finally return the user to the browser
		return user;
	},
	async signIn(parent, { email, password }, ctx, info) {
		// 1. check if there is a user with that email
		const user = await ctx.db.query.user({ where: { email } });
		if (!user) {
			throw new Error(`No such user for email ${email}`);
		}
		// 2. check if their password is correct
		const valid = await bcrypt.compare(password, user.password);
		if (!valid) {
			throw new Error("There's an issue with a password");
		}
		// 3. generate the JWT token
		const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
		// 4. Set the cookie with the token
		ctx.response.cookie('token', token, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
		});
		// 5. return the user
		return user;
	},
	signOut(parent, data, ctx, info) {
		// 1. delete jwt token
		ctx.response.clearCookie('token');
		// 2. return empty user object
		return { message: 'Goodbye!' };
	},
	async requestReset(parent, args, ctx, info) {
		// 1. check if this is a real user
		const user = ctx.db.query.user({ where: { email: args.email } });
		if (!user) {
			throw new Error(`No such user as ${args.email}`);
		}
		// 2. Set a reset token and expiry on that user
		const resetToken = (await promisify(randomBytes)(20)).toString('hex');
		const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
		const res = await ctx.db.mutation.updateUser({
			where: { email: args.email },
			data: { resetToken, resetTokenExpiry }
		});
		// 3. Email them that reset token
		const mailRes = await transport.sendMail({
			from: 'neeme@creativetrumpet.ee',
			to: args.email,
			subject: 'Your Password Reset email',
			html: makeANiceEmail(`
			Your Password Reset Token is here!
			\n\n
			<a href=${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}>Reset password</a>
			`)
		});

		return { message: 'Thanks' };
	},
	async resetPassword(parent, args, ctx, info) {
		// 1. check if the passwords match
		if (args.password !== args.confirmPassword) {
			throw new Error("Your passwords don't match");
		}
		// 2. check if reset token is legit
		// 3. check if it's expired
		const [ user ] = await ctx.db.query.users({
			where: {
				resetToken: args.resetToken,
				resetTokenExpiry_gte: Date.now() - 3600000
			}
		});
		if (!user) {
			throw new Error('This token is either invalid or expired');
		}
		// 4. hash the new password
		const password = await bcrypt.hash(args.password, 10);
		// 5. save the new password and remoe the old resetToken fields
		const updatedUser = await ctx.db.mutation.updateUser({
			where: {
				email: user.email
			},
			data: {
				password,
				resetToken: null,
				resetTokenExpiry: null
			}
		});
		// 6. generate JWT
		const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
		// 7. Set the JWT cookie
		ctx.response.cookie('token', token, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 365
		});
		// 8. return the new user
		return updatedUser;
	},
	async updatePermissions(parent, args, ctx, info) {
		// 1. check if logged in
		if (!ctx.request.userId) {
			throw new Error('You must be logged in!');
		}
		// 2. query the current user
		const currentUser = await ctx.db.query.user({ where: { id: ctx.request.userId } }, info);
		console.log(currentUser);
		// 3. chekc if they have permissions to do this
		hasPermission(currentUser, [ 'ADMIN', 'PERMISSIONUPDATE' ]);
		// 4. update the permissions
		return ctx.db.mutation.updateUser(
			{
				data: {
					permissions: {
						set: args.permissions
					}
				},
				where: {
					id: args.userId
				}
			},
			info
		);
	},
	async addToCart(parent, args, ctx, info) {
		// 1. make sure they are signed
		const { userId } = ctx.request;
		if (!userId) throw new Error('You must sign in first');
		// 2. query the users current cart
		const [ existingCartItem ] = await ctx.db.query.cartItems({
			where: {
				user: { id: userId },
				item: { id: args.id }
			}
		});
		// 3. check if that item is alredy in the cart
		if (existingCartItem) {
			console.log('This item is already in the cart');
			return ctx.db.mutation.updateCartItem({
				where: { id: existingCartItem.id },
				data: { quantity: existingCartItem.quantity + 1 }
			});
		}
		// 4. if it's not, create a fresh CartItem for that user!
		return ctx.db.mutation.createCartItem(
			{
				data: {
					user: {
						connect: { id: userId }
					},
					item: {
						connect: {
							id: args.id
						}
					}
				}
			},
			info
		);
	},
	async removeFromCart(parent, args, ctx, info) {
		// 1. Find the cart item
		const cartItem = await ctx.db.query.cartItem(
			{
				where: {
					id: args.id
				}
			},
			`{ id, user { id }}`
		);
		// 1.5 Make sure we found an item
		if (!cartItem) throw new Error('No CartItem Found!');
		// 2. Make sure they own that cart item
		if (cartItem.user.id !== ctx.request.userId) {
			throw new Error('Cheatin huhhhh');
		}
		// 3. Delete that cart item
		return ctx.db.mutation.deleteCartItem(
			{
				where: { id: args.id }
			},
			info
		);
	},
	async createOrder(parent, args, ctx, info) {
		// 1. query the current user and make sure they are signed in
		const { userId } = ctx.request;
		if (!userId) throw new Error('You must be signed in to complete the order.');
		const user = await ctx.db.query.user(
			{ where: { id: userId } },
			`{
				id
				name 
				email 
				cart { 
					id 
					quantity 
					item{ 
						title 
						price 
						id 
						description 
						image
						largeImage
					}
				}
			}`
		);
		// 2. recalculate the total for the price
		const amount = user.cart.reduce(
			(tally, cartItem) => (tally = tally + cartItem.quantity * cartItem.item.price),
			0
		);
		console.log(`Going to charge for an amount of ${amount}`);
		// 3. create the stripe charge (turn token into money)
		const charge = await stripe.charges.create({
			amount,
			currency: 'EUR',
			source: args.token
		});
		// 4. convert the CartItems to OrderItems
		const orderItems = user.cart.map((cartItem) => {
			const orderItem = {
				...cartItem.item,
				quantity: cartItem.quantity,
				user: {
					connect: { id: userId }
				}
			};
			delete orderItem.id;
			return orderItem;
		});
		// 5. create th Order
		const order = await ctx.db.mutation.createOrder({
			data: {
				total: charge.amount,
				charge: charge.id,
				items: { create: orderItems },
				user: { connect: { id: userId } }
			}
		});
		// 6. Clean up - clear the users cart, delete cartItems
		const cartItemIds = user.cart.map((cartItem) => cartItem.id);
		await ctx.db.mutation.deleteManyCartItems({
			where: { id_in: cartItemIds }
		});
		// 7. return the Order to the client
		return order;
	}
};

module.exports = Mutations;
